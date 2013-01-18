typedef int ElementType;
/* START: fig3_45.txt */
#ifndef _Stack_h
#define _Stack_h

struct StackRecord;
typedef struct StackRecord *Stack;

int IsEmptyStack(Stack S);
int IsFullStack(Stack S);
Stack CreateStack(int MaxElements );
void DisposeStack(Stack S );
void MakeEmptyStack(Stack S );
void Push( ElementType X, Stack S );
ElementType Top( Stack S );
void Pop( Stack S );
ElementType TopAndPop( Stack S );

#endif  /* _Stack_h */

/* END */
