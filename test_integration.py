import subprocess
import time
import pytest

# might need to use "docker-compose" on some Linux distros
COMPOSE = ["docker", "compose"]


# start relays
@pytest.fixture(scope="module", autouse=True)
def relay_stack():
    subprocess.run(
        [*COMPOSE, "up", "-d", "--build", "entry", "middle", "exit"],
        check=True,
    )
    time.sleep(4) # may need to change this by machine -> it takes ~2-3 sec. on my VM
    yield
    subprocess.run([*COMPOSE, "down", "--remove-orphans"], check=True)

# connect to http://example.com, assert HTTP 200 OK response is received by client
def test_example_com_returns_200():
    result = subprocess.run(
        [
            *COMPOSE, "run", "--rm",
            "-T",
            "client",
        ],
        input=b"http://example.com\n",
        capture_output=True,
        timeout=30,
    )

    stdout = result.stdout.decode(errors="replace")

    print("\n--- client stdout ---\n", stdout)

    assert "200 OK" in stdout, (
        f"Failure! Unexpected output:\n{stdout}"
    )