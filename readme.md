## Simple encryption and decryption algorithms for Cybersecurity course.

> [!CAUTION]
> Some terminals might delete invisible characters.

### Options:

-   **-u --using** \<algorithm>\
    (required) Specifies which algorithm to use.\
    example:\
    --using des

    - hill\
      key: a string presentation of list of lists of integers (as a square matrix) or a string which length is some power of two.
    
    - vigenere
    
    - auto-key
    
    - des\
      key: String of 8 ascii characters\
      text: String of any number of characters if encrypting or a multiple of 8 characters if decrypting.

- **-t --text** \<string>\
    (required) Plaintext to be encrypted or ciphertext to be decrypted.\
    Some algorithms require specific formatting of the text (see --use).
 
- **-k --key** \<string>\
    (required) A symmetric key used for cryption.\
    Some algorithms require specific formatting of the key (see --use).

- **-e --encrypt**\
    If set, the algorythm will encrypt the text using the key. Otherwise, the algorithm will decrypt instead.

- **-v --verbose**\
    Makes the algorithm also print intermediate products. 
