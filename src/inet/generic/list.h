/**
*   @file list.h
*   list.c's Interface.
*/

#ifndef __LIST_H
#define	__LIST_H

typedef	void *listElementT;

typedef	struct listCDT *listADT;

/* Creates new list and initializes the comparation function. It also sets the
 * size of the data type the list is going to work with.
 * If there is some problem it returns NULL. */

listADT
NewList(int (*fn)(listElementT elem1, listElementT elem2), size_t tam);

void	Insert(listADT list, listElementT element);

int	Delete(listADT list, listElementT element);

int	ListIsEmpty(listADT list);

int     ListNodesQty(listADT list);

int	ElementBelongs(listADT list, listElementT element);

void	SetBegin(listADT list);

int	GetDato(listADT list, listElementT element);

void	FreeList(listADT list);

listElementT retrieveData(listADT list, listElementT elem);
#endif
