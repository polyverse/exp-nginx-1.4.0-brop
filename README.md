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
        docker run --rm --link vuln-target -it 507760724064.dkr.ecr.us-west-2.amazonaws.com/exp-nginx-1.4.0-64

    TBD: Using this thing...
```
