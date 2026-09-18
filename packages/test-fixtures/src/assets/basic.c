#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
  #define SECTION_ATTR __declspec(allocate(".text"))
#else
  #define SECTION_ATTR __attribute__((section(".text")))
#endif

#if defined(_WIN32)

SECTION_ATTR
__declspec(noinline)
unsigned char test_shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0xC3
};

#else

__attribute__((used))
__attribute__((retain))

SECTION_ATTR
unsigned char test_shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0xC3
};

#endif

void run_test_shellcode(void) {
    void (*volatile f)(void) = (void (*)(void))test_shellcode;
    f();
}

typedef struct node {
    int a;
    char *b;
    struct node *n;
} node;

typedef struct {
    node *head;
    size_t n;
} pool;

struct Person {
    char name[50];
    int age;
    float height;
};

static volatile const struct Person juliet = {
    "Jane",
    20,
    1.88f
};

node* foo_make(int x);
node* bar_link(node *p, node *q);
pool* baz_pool(size_t n);
void qux_fill(pool *p);
void zap_free(pool *p);
void max_depth();
void self_call();
void struct_test();

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
    struct_test();
    return 0;
}

void max_depth_call() {
    max_depth_1();
}

void max_depth_1() {
    max_depth_2();
}

void max_depth_2() {
    max_depth_3();
}

void max_depth_3() {
    max_depth_4();
}

void max_depth_4() {
    max_depth_5();
}

void max_depth_5() {
    max_depth_6();
}

void max_depth_6() {
    return;
}

void self_call() {
    self_call();
}

void print_person(struct Person *person)
{
    printf("Name: %s\n", person->name);
    printf("Age: %d\n", person->age);
    printf("Height: %.2f\n", person->height);
}

void struct_test()
{
    struct Person alice = {
        .name = "Alice",
        .age = 25,
        .height = 1.68f
    };
    
    struct Person *john = malloc(sizeof(struct Person));
    strcpy(john->name, "John");
    john->age = 30;
    john->height = 1.75f;

    printf("alice.name = %s\n", alice.name);
    printf("alice.age = %d\n", alice.age);
    printf("alice.height = %.2f\n", alice.height);

    printf("juliet.name = %s\n", juliet.name);
    printf("juliet.age = %d\n", juliet.age);
    printf("juliet.height = %.2f\n", juliet.height);

    printf("john->name = %s\n", john->name);
    printf("john->age = %d\n", john->age);
    printf("john->height = %.2f\n", john->height);
}

__attribute__((noinline))
void stack_var_target(int seed) {
    volatile int probe = seed;
    probe += 7;
    probe *= 3;
    int result = probe;
    (void)result;
}