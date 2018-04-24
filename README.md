EMPIRE with TOR-ified listener http_tor.

- On launch the listener assembles a Tor+Proxy package to deploy on Victim machine.

- The generated Tor+Proxy ("update.zip" is manually hosted on a clearnet location)

- The listener is stopped and reconfigured including the now known clearnet location of update.zip

- The listener attaches to a HiddenService running on the local mashine and is protected by a HiddenServiceAuth cookie

- The generated stager downloads and deploys update.zip on the victim mashine and connects to the HiddenServiceListener via Tor

