/*
 *  * Copyright 2014 David Coffill
 *   * Licensed under the terms of the GPLv2
 *    */

#include "heap.h"
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mutex.h>

struct heap* init_heap(int capacity)
{
	int i;
	struct heap *heap = (struct heap *)kmalloc(sizeof(struct heap), GFP_KERNEL);
	if (unlikely(heap == NULL)) {
		goto out;
	}

	heap->data = (struct heap_data *)kmalloc(sizeof(struct heap_data) * size, GFP_KERNEL);
	if (unlikely(heap->data == NULL)) {
		kfree(heap);
		goto out;
	}

	for (i = 0; i < capacity; i++) {
		heap->data->index = i;
	}

	mutex_init(&heap->lock);
	init_waitqueue_head(&heap->read_queue);
	heap->capacity = capacity; /* array is 1 bigger than size we're given, since index 0 unused */
	heap->size = 0;

out:
	return heap;
}

void free_heap(struct heap *heap)
{
	kfree(heap->data);
	kfree(heap);
}


/* Insert entry into the heap */
int heap_insert(struct heap *heap, int *key)
{
	if (heap->size == heap->capacity) {
		return -1;
	}
	int i = ++heap->size - 1;
	heap->data[i]->key = key;
	while (i != 0 && *(heap->data[parent(i)]->key) > *(heap->data[i]->key)) {
		swap(&heap->data[i], &head->data[parent(i)]);
		i = parent(i);
	}

	return 0;
}

void heap_dec_key(struct heap *heap, int i)
{
	while (i != 0 && *(heap->data[parent(i)]->key) > *(heap->data[i]->key)) {
		swap(&heap->data[i], &head->data[parent(i)];
		i = parent(i);
	}
}


/* Delete the minimum item in the heap, then correct order and shape properties */
int *delete_min(struct heap *heap)
{
	int *root;

	if (heap->size <= 0) {
		root = NULL;
		goto out;
	}

	if (heap->size == 1) {
		heap->size--;
		root = heap->data[0]->key;
		goto out;
	}

	root = heap->data[0]->key;
	heap->data[0]->key = heap->data[--heap->size]->key;

	heap_minheapify(heap, 0);

out:
	return root;
}

static void heap_minheapify(struct heap *heap, int i)
{
	int l, r, smallest;
	smallest = i;
	do {
		l = left(i);
		r = right(i);
		if (l < heap->size && *(heap->data[l]->key) < *(heap->data[i]->key)) {
			smallest = l;
		}
		if (r < heap->size && *(heap->data[r]->key) < *(heap->data[smallest]->key)) {
			smallest = r;
		}
		if (smallest != i) {
			swap(&heap->data[i], &head->data[smallest];
			i = smallest;
		} else {
			break;
		}
	} while (1);
}


/* return index of parent node in heap */
static inline int parent(int position)
{
	return (position-1)/2; /* floor(pos/2) */
}


/* return index of left child node in heap */
static inline int left(int position)
{
	return 2*position + 1;
}

/* return index of right child node in heap */
static inline int right(int position)
{
	return 2*position + 2;
}

static inline void swap(struct heap_data *x, struct heap_data *y)
{
	int *temp_key = x->key;
	x->key = y->key;
	y->key = temp_key;
}
