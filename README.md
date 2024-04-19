# ASHIRT-c2-ingestors
These python scripts monitor log files for changes, and attempt to intelligently route logged task events to an ASHIRT instance for display in the timeline.

The ingestor is installed on the C2 platform, but requires values from the ASHIRT server first for operation.

# Instalation
1. Create a Headless User to submit logs (Profile Dropdown > Admin > Create Headless User). Record API key and secret.
2. On the C2 server, copy `<C2>-ingestor.py` and `requirements.txt` to `/opt/ASHIRT-Log-Ingestor/`.
3. Create a venv: `python3 -m venv /opt/ASHIRT-Log-Ingestor`
3. Copy `ingestor.service` to `/etc/systemd/system/` and update the environment variables defined in the service file according to your ashirt deployment. Update the python file invoked in the `ExecStart` line to be the correct one for your chosen C2.
3. `daemon-reload` and start the ingestor service.

# Status
- Cobalt Strike lightly tested.
- Brute Ratel a lightly tested. Looks like beacon IDs are reused by Brute Ratel when beacons are killed. This results in the BR ingestor using old cached data from the killed beacon for commands picked up by the new beacon.
- Mythic untested.