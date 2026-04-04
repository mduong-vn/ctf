#include <stdio.h>
#include <stdlib.h>

int main() {

    int seed = 4733;
    int so_nha_cai[7];

    for (int round = 1; round <= 11; round++) {

        srand(seed);

        printf("round%d = [", round);

        for (int i = 0; i <= 6; i++) {
            int v1, v4;

            do {
                v1 = 1;
                v4 = rand() % 37 + 1;

                for (int j = 0; j < i; j++)
                    if (v4 == so_nha_cai[j]) v1 = 0;

            } while (!v1);

            so_nha_cai[i] = v4;

            printf("%d", v4);
            if (i != 6) printf(", ");
        }

        printf("]\n");

        /* lấy seed round tiếp theo từ state hiện tại */
        seed = rand() % 4919;
    }

    return 0;
}