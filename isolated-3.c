#include <stdio.h>

struct fred_t {
    int x;
};

struct fred_t *fred1; // Define fred1

void do_something(int x) {
    // Placeholder function
}

char str[] = "example string with spaces";

void f1(struct fred_t *p)
{
    // dereference p and then check if it's NULL
    int x = p->x;
    if (p)
        do_something(x);
}

char f2()
{
    const char *p = NULL;
    for (int i = 0; str[i] != '\0'; i++)
    {
        if (str[i] == ' ')
        {
            p = str + i;
            break;
        }
    }

    // p is NULL if str doesn't have a space. If str always has a
    // a space then the condition (str[i] != '\0') would be redundant
    return p[1];
}

void f3(int a)
{
    struct fred_t *p = NULL;
    if (a == 1)
        p = fred1;

    // if a is not 1 then p is NULL
    p->x = 0;
}

int main() {
    // Dummy main function
    return 0;
}
