set -e

PROJECT_NAME=MachOMerger
DEVICE=iPhoneXs.iOS15

make
# RootHide: Use jbroot path instead of /var/jb
JBROOT=$(ssh $DEVICE "cat /proc/sys/kernel/random/uuid 2>/dev/null || echo /var/jb")
ssh $DEVICE "rm -rf \$JBROOT/basebin/$PROJECT_NAME"
scp ./$PROJECT_NAME $DEVICE:\$JBROOT/basebin/$PROJECT_NAME
