#include <stdio.h>

int main(void) {
    int i = 1;
    int state = 0;

    while (1) {
        switch (state) {

            case 0: // Check loop condition
                if (i <= 100)
                    state = 1;
                else
                    state = 99;
                break;

            case 1: // Divisible by 15?
                if (i % 15 == 0)
                    state = 2;
                else
                    state = 3;
                break;

            case 2: // FizzBuzz
                printf("FizzBuzz\n");
                state = 10;
                break;

            case 3: // Divisible by 3?
                if (i % 3 == 0)
                    state = 4;
                else
                    state = 5;
                break;

            case 4: // Fizz
                printf("Fizz\n");
                state = 10;
                break;

            case 5: // Divisible by 5?
                if (i % 5 == 0)
                    state = 6;
                else
                    state = 7;
                break;

            case 6: // Buzz
                printf("Buzz\n");
                state = 10;
                break;

            case 7: // Number
                printf("%d\n", i);
                state = 10;
                break;

            case 10: // Increment
                i++;
                state = 0;
                break;

            case 99: // Exit
                return 0;

            default:
                return 1;
        }
    }
}