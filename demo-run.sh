#!/bin/bash
docker run -it -v $PWD:/base --link vnginx --entrypoint /bin/bash exp-nginx-1.4.0-brop

