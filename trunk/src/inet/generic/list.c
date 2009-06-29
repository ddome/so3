#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>

#include "list.h"

/* List header */
struct listCDT
{
	int qty;
	struct nodeCDT *nodes;
	int (*compare)(listElementT elem1, listElementT elem2);
	size_t size;
	struct nodeCDT *actual;
};

typedef struct nodeCDT
{
	listElementT data;
	struct nodeCDT *tail;
} nodeCDT;

static void
Error(const char *msg)
{
	printf(msg);
	exit(EXIT_FAILURE);
}

listElementT
retrieveData(listADT list, listElementT elem)
{
    int finished = 0;
    listElementT res = malloc(list->size);

    if (res == NULL)
    {
        printf("Error in malloc\n");
        return NULL;
    }

    if (!ElementBelongs(list, elem))
        return NULL;

    SetBegin(list);
    while (finished == 0 && GetDato(list, res))
    {
        if ((*list->compare)(res, elem) == 0)
            finished = 1;
    }

    return res;
}

listADT
NewList(int (*fn)(listElementT elem1, listElementT elem2), size_t size)
{
	listADT aux;

	if (fn == NULL || size == 0)
		return NULL;

	if ((aux = malloc(sizeof(struct listCDT))) == NULL)
		Error("No place available\n");

	aux->qty = 0;
	aux->nodes = NULL;
	aux->compare = fn;
	aux->size = size;
	aux->actual = NULL;

	return aux;
}

int
ListIsEmpty(listADT list)
{
    return list->nodes == NULL;
}

int
ListNodesQty(listADT list)
{
    return list->qty;
}

static nodeCDT *
ListTail(nodeCDT *internList)
{
	if (internList == NULL)
		Error("You are trying to access to an empty list.\n");

	return internList->tail;
}

void
SetBegin(listADT list)
{
	list->actual = list->nodes;
}

int
GetDato(listADT list, listElementT element)
{
	if (list->actual == NULL)
		return 0;

	memcpy(element, list->actual->data, list->size);
	list->actual = ListTail(list->actual);

	return 1;
}

void
Insert(listADT list, listElementT element)
{
	nodeCDT *prev, *rec, *aux;

	prev = rec = list->nodes;

	while (rec != NULL && (*list->compare)(rec->data, element) == -1)
	{
		prev = rec;
		rec = ListTail(rec);
	}

	/* No duplicates */
	if (rec != NULL && (*list->compare)(rec->data, element) == 0) 
	{
		printf("Duplicated element\n");
		return;
	}

	if ((aux = malloc(sizeof(nodeCDT))) == NULL)
		Error("There is no place for another node.\n");

	aux->tail = rec;

	if ((aux->data = malloc(list->size)) == NULL)
	{
		free(aux);
		Error("No place for another node.\n");
	}

	list->qty++;
	memcpy(aux->data, element, list->size);

	if (prev == rec) /* it is the first */
		list->nodes = aux;
	else
		prev->tail = aux;
}

int
Delete(listADT list, listElementT element)
{
	nodeCDT *prev, *rec;

	rec = prev = list->nodes;

	while (rec != NULL && (*list->compare)(rec->data, element) == -1)
	{
		prev = rec;
		rec = ListTail(rec);
	}

	/* did not find it */
	if (rec == NULL || (*list->compare)(rec->data, element) != 0)
	{
		return 0;
	}

	/* Delete it! */
	if (prev == rec)
		list->nodes = prev->tail;
	else
		prev->tail = rec->tail;

	if (rec == list->actual)
		list->actual = ListTail(list->actual);

	list->qty--;
	
	free(rec->data);
	free(rec);

	return 1;
}

int
ElementBelongs(listADT list, listElementT element)
{
	nodeCDT *actual;
	void *data;
	int res;

	actual = list->actual;

	if ((data = malloc(list->size)) == NULL)
		Error("Could not allocate memory.\n");

	SetBegin(list);

	while (GetDato(list, data) && (*list->compare)(data, element) == -1)
		;

	list->actual = actual;

	res = data != NULL && (*list->compare)(data, element) == 0;
	
	free(data);

	return res;
}

void
FreeList(listADT list)
{
    nodeCDT *aux;

    while (!ListIsEmpty(list))
    {
        aux = list->nodes;
        list->nodes = aux->tail;
        free(aux->data);
        free(aux);
    }
    free(list);
}

