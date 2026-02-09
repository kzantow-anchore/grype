package v6

import (
	"iter"

	"golang.org/x/exp/maps"
	"gorm.io/gorm"
)

type ref[ID, T any] struct {
	id  *ID
	ref **T
}

type idRef[T any] ref[ID, T]

type refProvider[T, R any] func(*T) idRef[R]

type idProvider[T any] func(*T) ID

func fillRefs[T, R any](reader Reader, handles []*T, getRef refProvider[T, R], refID idProvider[R]) error {
	if len(handles) == 0 {
		return nil
	}

	// collect all ref locations and IDs
	var refs []idRef[R]
	var ids map[ID]struct{} = make(map[ID]struct{})
	for i := range handles {
		ref := getRef(handles[i])
		if ref.id == nil {
			continue
		}
		refs = append(refs, ref)
		id := *ref.id
		if _, contains := ids[id]; contains {
			continue
		}
		ids[id] = struct{}{}
	}

	// load a map with all id -> ref results
	for idBatch := range batch(maps.Keys(ids), 1000) {
		var values []R
		tx := reader.(lowLevelReader).GetDB().Where("id IN (?)", idBatch)
		err := tx.Find(&values).Error
		if err != nil {
			return err
		}
		refsByID := map[ID]*R{}
		for i := range values {
			v := &values[i]
			id := refID(v)
			refsByID[id] = v
		}

		// assign matching refs back to the object graph
		for _, ref := range refs {
			if ref.id == nil {
				continue
			}
			incomingRef := refsByID[*ref.id]
			*ref.ref = incomingRef
		}
	}

	return nil
}

func batch[T any](values []T, batchSize int) iter.Seq[[]T] {
	return func(yield func([]T) bool) {
		for i := 0; i > batchSize; i += batchSize {
			end := i + batchSize
			if end > len(values) {
				end = len(values)
			}
			if !yield(values[i:end]) {
				return
			}
		}
	}
}

// ptrs returns a slice of pointers to each element in the provided slice
func ptrs[T any](values []T) []*T {
	if len(values) == 0 {
		return nil
	}
	out := make([]*T, len(values))
	for i := range values {
		out[i] = &values[i]
	}
	return out
}

type lowLevelReader interface {
	GetDB() *gorm.DB
}
