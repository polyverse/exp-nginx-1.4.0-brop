# Container for brop exploit as described here: http://www.scs.stanford.edu/brop/

## Usage
```
USAGE

    This project is of the familiar form:
        bash build.sh
        bash test.sh
        bash publish.sh

    First run a container to attack:
        docker run -it --rm --name vuln-target 507760724064.dkr.ecr.us-west-2.amazonaws.com/vuln-nginx-1.4.0-64

    Then run this exploit to attack it:
        docker run --rm --link vuln-target -it 507760724064.dkr.ecr.us-west-2.amazonaws.com/exp-nginx-1.4.0-brop-64

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
