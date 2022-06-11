# DEPRECATION NOTICE

Please note that this repository has been deprecated and is no longer actively maintained by Polyverse Corporation.  It may be removed in the future, but for now remains public for the benefit of any users.

Importantly, as the repository has not been maintained, it may contain unpatched security issues and other critical issues.  Use at your own risk.

While it is not maintained, we would graciously consider any pull requests in accordance with our Individual Contributor License Agreement.  https://github.com/polyverse/contributor-license-agreement

For any other issues, please feel free to contact info@polyverse.com

---

# Container for brop exploit as described here: http://www.scs.stanford.edu/brop/

## Docker Image
https://hub.docker.com/repository/docker/polyverse/exp-nginx-1.4.0-brop

## Usage
```
USAGE

    This project is of the familiar form:
        bash build.sh
        bash test.sh
        bash publish.sh

    First run a container to attack (vulnerable OR safe):
        docker run -it --rm --name target polyverse/vulnerable-nginx-1.4.0:base
    -OR-
        docker run -it --privileged --rm --name target 507760724064.dkr.ecr.us-west-2.amazonaws.com/safe-nginx-1.4.0-dev
    -OR-
        docker run -it --privileged --rm --name target 507760724064.dkr.ecr.us-west-2.amazonaws.com/safe-nginx-1.4.0-rel

    Then run this exploit to attack it:
        docker run --rm --link target -it polyverse/exp-nginx-1.4.0-brop [-v] [p] [target-name-or-ip]
    For example:
    ```
    docker run --rm --link target -it polyverse/exp-nginx-1.4.0-brop target
    ```
    -OR-
    ```
    # interactive prompts
    docker run --rm --link target -it polyverse/exp-nginx-1.4.0-brop -p target
    ```


RUNNING BROP.RB

    The brop.rb program can be invoked manually using:

        ./brop.rb [-v] [-p] [target-name-or-ip]

    The -v option enables verbose mode which produces more informational output.  Leaving this option out
    reduces the output to just the essential information.

    The -p option will interactively prompt the user to hit <enter> before it proceeds to the next BROP phase

    If the targete-name-or-ip is missing, localhost is assumed.

NOTES

    SAVING STATE:  The brop.rb program attempts to save state as it goes through the phases of its attack such that
    if it has to restart, it can do so using information discovered from the previous successful portion of the
    attack.  The state is in a file called 'state.json'.  This can also be useful for debugging if you know what
    you're doing, but in general, it is more reliable to do a full attack.  If the attack fails for mysterious
    reasons, your first step should be to delete 'state.json' and rerun the attack.

ISSUES:
    - Occasionally declares the victim 'Not vulnerable' or 'Overflow of 5000 didn't crash, assuming not
      vulnerable'.  Restarting the victim nginx usually resolves this.

    - Canary reads all zeroes.  Cause unknown.  Remove the 'state.json' file and rerun the attack usually
      resolves this.
```
