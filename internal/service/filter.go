package clouddirector

import (
	"fmt"
	"strings"
)

type LogicalOp string

const (
	And LogicalOp = ";"
	Or  LogicalOp = ","
)

type ComparisonOp string

const (
	Eq ComparisonOp = "=="
	Ne ComparisonOp = "!="
	Gt ComparisonOp = "=gt="
	Ge ComparisonOp = "=ge="
	Lt ComparisonOp = "=lt="
	Le ComparisonOp = "=le="
)

type Filter interface {
	isFilter()
}

type Condition struct {
	Field    string
	Operator ComparisonOp
	Value    any
}

func (Condition) isFilter() {}

type Group struct {
	Op      LogicalOp
	Filters []Filter
}

func (Group) isFilter() {}

func ToFilterString(filter Filter) (string, error) {
	switch f := filter.(type) {
	case Condition:
		op := string(f.Operator)
		return fmt.Sprintf("%s%s%v", f.Field, op, f.Value), nil
	case Group:
		if len(f.Filters) == 0 {
			return "", nil
		}
		delim := string(f.Op)
		parts := make([]string, 0, len(f.Filters))
		for _, sub := range f.Filters {
			part, err := ToFilterString(sub)
			if err != nil {
				return "", err
			}
			if part != "" {
				parts = append(parts, part)
			}
		}

		// if we do not have any particular nodes, we return to normal join
		expr := strings.Join(parts, delim)

		// if it is a compound group and there is more than one element, we enclose it in brackets
		if len(parts) > 1 {
			return fmt.Sprintf("(%s)", expr), nil
		}
		return expr, nil
	}

	return "", nil
}
