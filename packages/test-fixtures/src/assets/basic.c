#include <stdlib.h>
#include <string.h>

typedef struct node {
    int a;
    char *b;
    struct node *n;
} node;

typedef struct {
    node *head;
    size_t n;
} pool;

node* foo_make(int x);
node* bar_link(node *p, node *q);
pool* baz_pool(size_t n);
void qux_fill(pool *p);
void zap_free(pool *p);

node* foo_make(int x) {
    node *p = (node*)malloc(sizeof(node));
    p->a = x ^ 0x55AA;
    p->b = strdup("weird_payload");
    p->n = NULL;
    return p;
}

node* bar_link(node *p, node *q) {
    if (!p) return q;
    p->n = q;
    return p;
}

pool* baz_pool(size_t n) {
    pool *p = (pool*)malloc(sizeof(pool));
    p->head = NULL;
    p->n = n;
    return p;
}

void qux_fill(pool *p) {
    node *h = NULL;
    for (size_t i = 0; i < p->n; i++) {
        node *t = foo_make((int)i * 31);
        h = bar_link(t, h);
    }
    p->head = h;
}

void zap_free(pool *p) {
    node *c = p->head;
    while (c) {
        node *nx = c->n;
        free(c->b);
        free(c);
        c = nx;
    }
    free(p);
}

void foo_comment(pool *p) {
    node *c = NULL;
    for (size_t i = 0; i < p->n; i++) {
        node *t = foo_make((int)i * 31);
        c = bar_link(t, c);
    }
    p->head = c;
}

void foo_rename_func(pool *p) {
    node *c = NULL;
    for (size_t i = 0; i < p->n; i++) {
        node *t = foo_make((int)i * 31);
        c = bar_link(t, c);
    }
    p->head = c;
}

__attribute__((used))
void im_orphaned(){
    char yea[] = "I have no parents";
}

int main() {
    pool *p = baz_pool(4);
    qux_fill(p);
    zap_free(p);
    return 0;
}
