import pytest

from aegisweave.ml import create_splits, fit_bundle


@pytest.fixture(scope="session")
def splits():
    # Half-size synthetic splits keep the real training pipeline fast enough for CI.
    return create_splits(seed=7, scale=.5)


@pytest.fixture(scope="session")
def bundle(splits):
    return fit_bundle(splits, seed=7)


@pytest.fixture(scope="session")
def bundle_dir(bundle, tmp_path_factory):
    path = tmp_path_factory.mktemp("model") / "active"
    bundle.save(path)
    return path
