set -e

PROJECT_NAME=systemhook.dylib
DEVICE=root@localhost
PORT=2223

make
# RootHide: Use jbroot path instead of /var/jb
ssh $DEVICE -p $PORT "rm -rf \$(jbroot)/basebin/$PROJECT_NAME"
scp -P$PORT ./$PROJECT_NAME $DEVICE:\$(jbroot)/basebin/$PROJECT_NAME
ssh $DEVICE -p $PORT "\$(jbroot)/basebin/jbctl rebuild_trustcache"
