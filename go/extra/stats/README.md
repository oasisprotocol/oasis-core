# Stats

Queries a node for network stats. Currently implemented per entity block
signature counts.

## Usage

```
$ stats/stats entity-signatures \
    --address unix:<node_dir>/internal.sock \
    --start-block 0 \
    --end-block 100 \
    --top-n 100

|Rank |Entity ID                                                       |Nodes |Signatures|
------------------------------------------------------------------------------------------
|1    |ef9ccfc825d5f0087e56937c697b46520f29f81e21d8a289218a4ebaef00509c|     6|       100|
|2    |4ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35|     1|        80|
...
