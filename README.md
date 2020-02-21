# Container for brop exploit as described here: http://www.scs.stanford.edu/brop/

## Usage
```
USAGE

    This project is of the familiar form:
        bash build.sh
        bash test.sh
        bash publish.sh

    First run a container to attack (vulnerable OR safe):
        docker run -it --rm --name target 507760724064.dkr.ecr.us-west-2.amazonaws.com/base-nginx-1.4.0
    -OR-
        docker run -it --privileged --rm --name target 507760724064.dkr.ecr.us-west-2.amazonaws.com/safe-nginx-1.4.0-dev
    -OR-
        docker run -it --privileged --rm --name target 507760724064.dkr.ecr.us-west-2.amazonaws.com/safe-nginx-1.4.0-rel

    Then run this exploit to attack it:
        docker run --rm --link target -it 507760724064.dkr.ecr.us-west-2.amazonaws.com/exp-nginx-1.4.0-brop

ISSUES:
    - Occasionally declares the victim 'Not vulnerable' or 'Overflow of 5000 didn't crash, assuming not
      vulnerable'.  Restarting the victim nginx usually resolves this.

    - Canary reads all zeroes.  Cause unknown.  Remove the 'state.json' file and rerun the attack usually
      resolves this.  
```
