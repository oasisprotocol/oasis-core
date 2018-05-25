# 3-node committee with known roles

When elected as a committee in epoch 1 nodes will be assigned the following roles:

* Node 1 will be elected `BackupWorker`.
* Node 2 will be elected `Worker`.
* Node 3 will be elected `Leader`.

To ensure deterministic elections with above results, you must set the contract ID to:
```
0000000000000000000000000000000000000000000000000000000000000000
```
