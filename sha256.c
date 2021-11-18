#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//get OS    
#if defined(_WIN32) || defined(_WIN64)
#define OS_WINDOWS
#elif defined(__linux__)
#define OS_LINUX
#elif defined(__APPLE__)
#define OS_MAC
#endif

//get word size and endianess
#if defined(__x86_64__) || defined(_M_X64)
#define WORD_SIZE 64
#define ENDIAN_LITTLE
#elif defined(__i386__) || defined(_M_IX86)
#define WORD_SIZE 32
#if defined(__LITTLE_ENDIAN__) || defined(_M_IX86)
#define ENDIAN_LITTLE
#elif defined(__BIG_ENDIAN__) || defined(_M_PPC)
#define ENDIAN_BIG
#endif
#endif

//DEBBUGING
#define DEBUG_PRINT

//function prototypes
int main_menu(unsigned char *data);
void sha256(unsigned char *data, unsigned int data_size, unsigned char *hash);
void print_hash(unsigned char *hash);

//main function
int main(int argc, char const *argv[])
{
    //create data buffer
    unsigned char data[64];

    //create data size variable
    unsigned int data_size = main_menu(data);

    //create hash buffer
    unsigned char hash[32];

    //call sha256 function
    sha256(data, data_size, hash);

    //print hash
    print_hash(hash);

    return 0;
} //end main

//main menu get a pointer to a buffer and a size

int main_menu(unsigned char *data)
{
    unsigned char *buff;
    buff = malloc(sizeof(data) * 64); //allocate memory for buffer

    //get user input
    while (1)
    {

        //clear screen
        #if defined(OS_LINUX)
            system("clear");
        #elif defined(OS_WINDOWS)
            system("cls");
        #elif defined(OS_MAC)
            system("clear");
        #endif
        
        //print welcome message in green
        printf("\033[1;32m");
        printf("ENEB451 - Final Project\n");
        printf("SHA 256 amd RSA implementation\n");
        printf("Coded by Ricardo / Kelvin\n");
        printf("\033[0m");
        
        //print main menu in blue bold
        printf("\033[1;34m");
        printf("\nMain Menu:\n");
        printf("1. Calculate SHA256 hash of a file\n");
        printf("2. Calculate SHA256 hash of a string\n");
        printf("3. Quit\n");
        printf("\033[0m");

        
        int choice;
        //print prompt in green bold
        printf("\033[1;32m");
        printf("\nEnter your choice: "); //prompt user for choice   
        scanf("%d", &choice);   //get user input
        printf("\033[0m");

        //consume newline
        getchar();
        
        switch (choice) //switch on choice
        {
            case 1: //case 1 - calculate hash of a file
                printf("\nEnter the name of the file: ");
                char file_name[256]; //create file name buffer
                scanf("%s", file_name); //get file name
                FILE *file = fopen(file_name, "rb"); //open file in read binary mode

                //check if file exists
                if (file == NULL) 
                {
                    printf("\nFile not found!\n"); //print error message
                    break; //break out of switch
                }

                fseek(file, 0, SEEK_END);   //move to end of file
                int file_size = ftell(file);    //get file size
                fseek(file, 0, SEEK_SET);   //move to start of file
                buff = realloc(buff, sizeof(unsigned char) * file_size);    //reallocate buffer to file size
                fread(buff, 1, file_size, file); //read file data into buffer
                fclose(file);   //close file
                data = realloc(data, file_size);    //reallocate data buffer
                memcpy(data, buff, file_size); //copy file data into data buffer
                free(buff); //free file data buffer
                break; //break out of switch

            case 2: //case 2 - calculate hash of string
                printf("\nEnter a string [max %lu chars]: ", sizeof(data)*8);   //print prompt
                fgets(data, sizeof(data)*8, stdin);   //get string from user
                fflush(stdin);  //flush stdin                
                return strlen(data);    //return string length

                
            case 3: //quit
                printf("\nGoodbye!\n"); //print goodbye message
                printf("\nPress any key to close program...\n");    //print prompt
                getchar();  //get user input
                free(data); //free data buffer
                exit(0);    //exit program
        } //end switch
    }//end while
} //end main menu





//sha algorithm implementation

/*right rotate function
    *
    *@param x - value to rotate
    *@param y - number of bits to rotate
    *
    *@return - rotated value
    */   
unsigned int right_rotate(unsigned int x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));  //return right rotated value
}

/*sigma 0 function
    * right rotate 2
    * xor with 0x5c
    * add 0x36
    * return result
    * @param x - 32 bit integer
    * @return 32 bit integer 
    */ 
unsigned int sigma_0(unsigned int x)    //x = 32 bit word
{
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3);  //return sigma 0 value
}

/*sigma 1 function
    * right rotate 2
    * xor with 0x36
    * add 0x5c
    * return result
    * @param x - 32 bit integer
    * @return 32 bit integer 
    */
unsigned int sigma_1(unsigned int x)
{
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10);  //return sigma 1 value
}

/*ch function
 *
 * @param x - 32 bit word to be hashed     
 * @param y - 32 bit word to be hashed
 * @param z - 32 bit word to be hashed
 *
 * @return 32 bit word hashed by ch function
 */
unsigned int ch(unsigned int x, unsigned int y, unsigned int z)   //x, y, z = 32 bit words
{
    return (x & y) ^ (~x & z);  //return ch value   
}

/*maj function XOR  x and y if x and y are equal, x and z if x and z are equal,   
 *
 * @param x - 32 bit word to be hashed     
 * @param y - 32 bit word to be hashed
 * @param z - 32 bit word to be hashed
 *
 * @return 32 bit word hashed by maj function
 */      
unsigned int maj(unsigned int x, unsigned int y, unsigned int z)   //x, y, z = 32 bit words
{
    return (x & y) ^ (x & z) ^ (y & z);  //return maj value
}


/*sha256 function
 *
 * @param data - pointer to data buffer
 * @param size - size of data buffer
 *
 * @return - pointer to hash buffer
 */
void sha256(unsigned char *data, unsigned int data_size, unsigned char *hash)
{
    //initialize hash values array (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19) 
    unsigned int H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

    //initialize round constants array (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
    unsigned int K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1,
        0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
        0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
        0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
        0xbef9a3f7, 0xc67178f2};

    //initialize variables
    unsigned int i, j, k;   //loop variables
    unsigned int w[64]; //array of 64 words
    unsigned int a, b, c, d, e, f, g, h;    //hash values
    unsigned int t1, t2;    //temporary variables
  
    
    #ifdef DEBUG_PRINT
    //printing DEBUG data   
    printf("\n***************************DEBUG DATA********************************\n");
    //print original data to console
    printf("\nOriginal data:\n");
    for(i = 0; i < data_size; i++)
    {        //print 32 bit words
        if(i % 4 == 0)
            printf("\n");   
        printf("%02x", data[i]);
    }
    printf("\n***********************END OF DEBUG DATA********************************\n");
    #endif //end of DEBUG data

    /*pre-processing of the original message*/

    //append the bit '1' to the message
    data[strlen(data)-1] = 0x80;

    #ifdef DEBUG_PRINT
    //printing DEBUG data
    printf("\n***************************DEBUG DATA********************************\n");
    //print original data to console
    printf("\nData after adding 1 at end:\n");
    for (i = 0; i < data_size; i++)
    {                        //print 32 bit words
        if (data[i] == 0x0a) //if new line
            data[i] = 0x00;  //replace new line with null
        if (i % 4 == 0)
            printf("\n");
        printf("%02x", data[i]);
    }
    printf("\n***********************END OF DEBUG DATA********************************\n");
    #endif //end of DEBUG data

    //append 0 <= k < 512 bits '0', such that the resulting message length (in bits) is congruent to 448 (mod 512)
    //(optimalization: zero-initialize the array)
    memset(data + data_size + 1, 0, 64 - (data_size + 1) % 64);     
    
    //append length of message (before pre-processing), in bits, as 32-bit big-endian integer
    data[data_size + 1 + 64 - (data_size + 1) % 64 - 4] = (data_size * 8) >> 24;    //most significant byte
    data[data_size + 1 + 64 - (data_size + 1) % 64 - 3] = (data_size * 8) >> 16;    //second most significant byte
    data[data_size + 1 + 64 - (data_size + 1) % 64 - 2] = (data_size * 8) >> 8;     //third most significant byte
    data[data_size + 1 + 64 - (data_size + 1) % 64 - 1] = (data_size * 8) >> 0;     //least significant byte

    #ifdef DEBUG_PRINT
    //printing DEBUG data
    printf("\n***************************DEBUG DATA********************************\n");
    //print original data to console
    printf("\nData after adding appening zeros:\n");
    for (i = 0; i < data_size; i++)
    {                        //print 32 bit words
        if (data[i] == 0x0a) //if new line
            data[i] = 0x00;  //replace new line with null
        if (i % 4 == 0)
            printf("\n");
        printf("%02x", data[i]);
    }
    printf("\n***********************END OF DEBUG DATA********************************\n");
    #endif //end of DEBUG data

    //process the message in successive 512-bit chunks
    for (i = 0; i < data_size + 1 + 64 - (data_size + 1) % 64; i += 64)
    {
        //break chunk into sixteen 32-bit big-endian words w[j], 0 ≤ j ≤ 15
        for (j = 0; j < 16; j++)
        {
            w[j] = (data[i + 4 * j] << 24) | (data[i + 4 * j + 1] << 16) | (data[i + 4 * j + 2] << 8) | (data[i + 4 * j + 3] << 0); //little endian
        }

        //extend the sixteen 32-bit words into sixty-four 32-bit words:
        for (j = 16; j < 64; j++)
        {
            w[j] = (w[j - 2] >> 17) | (w[j - 2] << (32 - 17)) ^ (w[j - 2] >> 19) | (w[j - 2] << (32 - 19)) ^ (w[j - 2] >> 10);  //sigma1(w[j-2])
        }

        //initialize working variables to current hash value: a, b, c, d, e, f, g, h
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        //compression function main loop (64 rounds)    
        for (j = 0; j < 64; j++)    
        {
            t1 = h + sigma_1(e) + ch(e, f, g) + K[j] + w[j]; //rotate right by one bit and add K(round constant) + w(message word)     
            t2 = sigma_0(a) + maj(a, b, c); //rotate right by one bit and add sigma0(a) + maj(a, b, c)
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }   //end of for loop

        //compute the intermediate hash value H(i) that is the hash value of the message block H(i-1)
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
        
        //append H to hash_value (in big-endian order) amd digest the message block
        for (j = 0; j < 8; j++)
        {
            hash[4 * j] = H[j] >> 24;       //most significant byte
            hash[4 * j + 1] = H[j] >> 16;   //second most significant byte
            hash[4 * j + 2] = H[j] >> 8;    //third most significant byte
            hash[4 * j + 3] = H[j] >> 0;    //least significant byte


            #ifdef DEBUG_PRINT  //print hash value to console
                printf("Digested data:\n");
                printf("\033[0;31m"); //red
                printf("\nH[%d] = %08x\t", j, H[j]);    //print hash value in hex
                printf("\033[0m"); //default
                printf("\033[1;33m"); //yellow
                printf("\tH[%d] = ", j);    
                for(k = 0; k < 32; k++)
                {           
                    printf("%d", (H[j] >> k) & 1);
                }
                printf("\033[0m"); //default
                printf("\n");
            #endif
            



        }//end of for loop
    }//end of for loop    
}//end of function

void print_hash(unsigned char *hash)
{
    int i; //loop variable

    //change color to yellow bold
    printf("\033[1;33m");
    for (i = 0; i < 32; i++)
    {
        printf("%02x", hash[i]);
        //print a space after every 4 bytes
        if ((i + 1) % 4 == 0)
        {
            printf(" ");
        }
    }
    printf("\n");
    //change color back to normal
    printf("\033[0m");

}