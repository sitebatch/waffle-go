package exporter

type StdoutExportOperation struct{}

type StdoutExportOperationArg struct{}

type StdoutExportOperationResult struct {
	Error error
}

func (StdoutExportOperationArg) IsArgOf(*StdoutExportOperation)        {}
func (*StdoutExportOperationResult) IsResultOf(*StdoutExportOperation) {}
