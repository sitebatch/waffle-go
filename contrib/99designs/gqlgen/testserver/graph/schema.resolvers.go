package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.62

import (
	"context"
	"fmt"

	"github.com/sitebatch/waffle-go/contrib/99designs/gqlgen/testserver/graph/model"
)

// CreateTodo is the resolver for the createTodo field.
func (r *mutationResolver) CreateTodo(ctx context.Context, input model.NewTodo) (*model.Todo, error) {
	return &model.Todo{
		Text: input.Text,
		ID:   "1",
		Done: false,
		User: &model.User{
			ID:   input.UserID,
			Name: fmt.Sprintf("user%s", input.UserID),
		},
	}, nil
}

// Todos is the resolver for the todos field.
func (r *queryResolver) Todos(ctx context.Context) ([]*model.Todo, error) {
	return []*model.Todo{
		{
			Text: "todo1",
			ID:   "1",
			Done: false,
			User: &model.User{
				ID:   "1",
				Name: "user1",
			},
		},
		{
			Text: "todo2",
			ID:   "2",
			Done: false,
			User: &model.User{
				ID:   "1",
				Name: "user1",
			},
		},
	}, nil
}

// SearchTodo is the resolver for the searchTodo field.
func (r *queryResolver) SearchTodo(ctx context.Context, id string, text string) ([]*model.Todo, error) {
	return []*model.Todo{
		{
			Text: text,
			ID:   id,
			Done: false,
			User: &model.User{
				ID:   "1",
				Name: "user1",
			},
		},
	}, nil
}

// Mutation returns MutationResolver implementation.
func (r *Resolver) Mutation() MutationResolver { return &mutationResolver{r} }

// Query returns QueryResolver implementation.
func (r *Resolver) Query() QueryResolver { return &queryResolver{r} }

type mutationResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
