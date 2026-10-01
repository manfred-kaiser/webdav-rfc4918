"""The fsspec filesystem as the programs that use fsspec use it: pandas, dask, pyarrow, zarr, xarray.

``test_fsspec_abstract.py`` checks the filesystem against fsspec's own conformance suite and
``test_fsspec_edge_cases.py`` against the corners of WebDAV. This module is what those two
cannot tell: what the *callers* do with a filesystem - the options they pass to every one
(``asynchronous=True``), how many writers they start at once, which paths they hand over.
Both bugs it found first - the options and the race to create a parent directory - were
invisible to the other two.

None of these libraries is a dependency: each test is skipped where its library is not
installed, so the usual run stays small. Install them to run these, e.g.::

    pip install pandas pyarrow "dask[dataframe]" zarr xarray
"""

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import fsspec
import pytest

from tests.credentials import AUTH
from webdav.fsspec import WebdavFileSystem


@pytest.fixture
def options(server_url: str) -> dict[str, Any]:
    """The storage options of every call below: pandas, dask and zarr call them ``storage_options``."""
    return {"base_url": server_url, "auth": AUTH}


@pytest.fixture
def filesystem(options: dict[str, Any]) -> WebdavFileSystem:
    return WebdavFileSystem(**options)


def _frame(rows: int = 1000) -> Any:
    pd = pytest.importorskip("pandas")
    np = pytest.importorskip("numpy")
    return pd.DataFrame(
        {
            "a": range(rows),
            "b": [f"x{i}" for i in range(rows)],
            "c": np.random.default_rng(0).random(rows),
        }
    )


# ---------------------------------------------------------------------------
# pandas
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["a.csv", "a.csv.gz", "a.json", "a.parquet"])
def test_pandas_writes_and_reads_a_file(options: dict[str, Any], name: str) -> None:
    pd = pytest.importorskip("pandas")
    if name.endswith(".parquet"):
        pytest.importorskip("pyarrow")
    frame = _frame()
    url = f"webdavs:///data/{name}"
    if name.endswith((".csv", ".csv.gz")):
        frame.to_csv(url, index=False, storage_options=options)
        back = pd.read_csv(url, storage_options=options)
    elif name.endswith(".json"):
        frame.to_json(url, orient="records", lines=True, storage_options=options)
        back = pd.read_json(url, orient="records", lines=True, storage_options=options)
    else:
        frame.to_parquet(url, storage_options=options)
        back = pd.read_parquet(url, storage_options=options)
    assert back.shape == (1000, 3)
    assert int(back.a.sum()) == sum(range(1000))


def test_pandas_reads_single_parquet_columns_by_ranges(
    options: dict[str, Any],
) -> None:
    pd = pytest.importorskip("pandas")
    pytest.importorskip("pyarrow")
    _frame().to_parquet("webdavs:///data/c.parquet", storage_options=options)
    back = pd.read_parquet(
        "webdavs:///data/c.parquet", columns=["b"], storage_options=options
    )
    assert list(back.columns) == ["b"]


def test_pandas_with_the_server_in_the_url(
    server_url: str, options: dict[str, Any]
) -> None:
    """``webdavs://host:port/path`` - the host used to be written to the server as a directory."""
    pd = pytest.importorskip("pandas")
    netloc = urlsplit(server_url).netloc
    _frame(3).to_csv(
        f"webdavs://{netloc}/data/h.csv", index=False, storage_options=options
    )
    assert pd.read_csv(
        f"webdavs://{netloc}/data/h.csv", storage_options=options
    ).shape == (3, 3)
    assert WebdavFileSystem(**options).find("/") == ["/data/h.csv"]


# ---------------------------------------------------------------------------
# dask: many writers at once
# ---------------------------------------------------------------------------


def test_dask_writes_partitions_in_parallel_into_a_new_directory(
    options: dict[str, Any],
) -> None:
    """Eight threads create ``/dk`` at once: the loser of that race must not fail."""
    dask = pytest.importorskip("dask")
    dd = pytest.importorskip("dask.dataframe")
    pd = pytest.importorskip("pandas")
    frame = pd.concat([_frame(250)] * 4)
    with dask.config.set(scheduler="threads"):
        dd.from_pandas(frame, npartitions=8).to_csv(
            "webdavs:///dk/part-*.csv", index=False, storage_options=options
        )
        assert (
            len(dd.read_csv("webdavs:///dk/part-*.csv", storage_options=options))
            == 1000
        )


def test_dask_parquet_dataset_with_the_processes_scheduler(
    options: dict[str, Any],
) -> None:
    """The filesystem is pickled into every worker process."""
    dask = pytest.importorskip("dask")
    dd = pytest.importorskip("dask.dataframe")
    pytest.importorskip("pyarrow")
    dd.from_pandas(_frame(), npartitions=4).to_parquet(
        "webdavs:///dk/pq", storage_options=options
    )
    with dask.config.set(scheduler="processes"):
        back = dd.read_parquet("webdavs:///dk/pq", storage_options=options)
        assert int(back.a.sum().compute()) == sum(range(1000))


# ---------------------------------------------------------------------------
# pyarrow
# ---------------------------------------------------------------------------


def test_pyarrow_reads_and_writes_through_the_filesystem(
    filesystem: WebdavFileSystem,
) -> None:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    ds = pytest.importorskip("pyarrow.dataset")
    pafs = pytest.importorskip("pyarrow.fs")
    arrow_fs = pafs.PyFileSystem(pafs.FSSpecHandler(filesystem))
    frame = _frame(30)
    table = pa.Table.from_pandas(frame.assign(g=frame.a % 3))
    pq.write_table(table, "/arrow/t.parquet", filesystem=arrow_fs)
    assert pq.read_table("/arrow/t.parquet", filesystem=arrow_fs).num_rows == 30
    # pyarrow compares the names it is given back with the directory it asked for:
    # absolute paths, as for every filesystem with a root.
    ds.write_dataset(
        table,
        "/arrow/ds",
        format="parquet",
        filesystem=arrow_fs,
        partitioning=["g"],
        partitioning_flavor="hive",
    )
    dataset = ds.dataset("/arrow/ds", filesystem=arrow_fs, partitioning="hive")
    assert dataset.to_table().num_rows == 30
    infos = arrow_fs.get_file_info(pafs.FileSelector("/arrow/ds", recursive=True))
    assert sum(i.path.endswith(".parquet") for i in infos) == 3


# ---------------------------------------------------------------------------
# zarr and xarray open the filesystem with ``asynchronous=True``
# ---------------------------------------------------------------------------


def test_zarr_opens_a_url_and_writes_chunks_in_parallel(
    options: dict[str, Any],
) -> None:
    zarr = pytest.importorskip("zarr")
    np = pytest.importorskip("numpy")
    group = zarr.open_group("webdavs:///z/u.zarr", mode="w", storage_options=options)
    if not hasattr(group, "create_array"):
        pytest.skip("zarr 3 is needed")
    array = group.create_array("x", shape=(200,), chunks=(10,), dtype="f8")
    array[:] = np.arange(200.0)
    again = zarr.open_group("webdavs:///z/u.zarr", mode="r", storage_options=options)
    assert float(again["x"][:].sum()) == sum(range(200))


@pytest.mark.filterwarnings("ignore:Consolidated metadata:UserWarning")
def test_xarray_writes_and_reads_zarr_through_a_url(options: dict[str, Any]) -> None:
    xr = pytest.importorskip("xarray")
    np = pytest.importorskip("numpy")
    pytest.importorskip("zarr")
    dataset = xr.Dataset({"t": (("i",), np.arange(20.0))})
    dataset.to_zarr("webdavs:///z/x.zarr", mode="w", storage_options=options)
    back = xr.open_zarr("webdavs:///z/x.zarr", storage_options=options)
    assert float(back.t.sum()) == sum(range(20))


# ---------------------------------------------------------------------------
# fsspec's own chained and mapped front doors, as callers use them
# ---------------------------------------------------------------------------


def test_a_zip_on_the_server_is_read_through_a_chained_url(
    filesystem: WebdavFileSystem, options: dict[str, Any]
) -> None:
    import io  # noqa: PLC0415
    import zipfile  # noqa: PLC0415

    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("one.csv", "a\n1\n")
        bundle.writestr("two.csv", "a\n2\n")
    filesystem.pipe_file("/arch.zip", archive.getvalue())
    members = fsspec.open_files("zip://*.csv::webdavs:///arch.zip", webdavs=options)
    assert [m.open().read() for m in members] == [b"a\n1\n", b"a\n2\n"]


def test_the_configuration_of_fsspec_can_name_the_server(
    server_url: str, tmp_path: Path
) -> None:
    """``FSSPEC_WEBDAVS`` (JSON) is how a program is pointed at a server without touching its code."""
    import json  # noqa: PLC0415
    import os  # noqa: PLC0415
    import subprocess  # noqa: PLC0415
    import sys  # noqa: PLC0415

    WebdavFileSystem(server_url, auth=AUTH).pipe_file("/a.txt", b"hello")
    environment = {
        **os.environ,
        "FSSPEC_WEBDAVS": json.dumps({"base_url": server_url, "auth": list(AUTH)}),
    }
    code = "import webdav.fsspec, fsspec; print(fsspec.open('webdavs:///a.txt').open().read().decode())"
    # our own interpreter and our own code
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code],
        env=environment,
        capture_output=True,
        text=True,
        check=True,
        cwd=tmp_path,
    )
    assert result.stdout.strip() == "hello"
