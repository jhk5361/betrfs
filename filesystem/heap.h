
/*
 *  * Copyright 2014 David Coffill
 *   * Licensed under the terms of the GPLv2
 *    */

#ifndef HEAP_H
#define HEAP_H
#include <linux/mutex.h>
#include <linux/sched.h>

struct heap_data {
	int *key;
	int index;
}

struct heap
{
	struct heap_data *data;
	int capacity;
	int size; /* index of last occupied place in heap */
	struct mutex lock;
	wait_queue_head_t read_queue;
};

struct heap *init_heap(int capacity);
void free_heap(struct heap *heap);

int heap_insert(struct heap *heap, int *key);
static inline int parent(int position);
static inline int left(int position);
static inline int right(int position);
void heap_dec_key(struct heap *heap, int i);
int *delete_min(struct heap *heap);
static void heap_minheapify(struct heap *heap, int i);

#endif
