package alg

// subgraphOrder helper class for sorting subgraphs, highest cost first.
type subgraphOrder []*Subgraph

func (a subgraphOrder) Len() int           { return len(a) }
func (a subgraphOrder) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a subgraphOrder) Less(i, j int) bool { return a[i].EstExecutionTime() > a[j].EstExecutionTime() }
