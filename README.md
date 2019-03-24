# Fully managed .NET AES implementation (based on AES-NI)

**Do not use this in production! This is a toy project to explore `System.Runtime.Intrinsics` and AES-NI**

Currently with support for ECB, CBC and GCM encrypt/decrypt (all NIST KATs passing). 
Adding all sorts of paddings is also supported, removing & verifying it is on my todo list...
Other modes of use may follow as well.

## AES key expansion performance

|                Method |     Mean |     Error |    StdDev |
|---------------------- |---------:|----------:|----------:|
| Aes128BitKeyExpansion | 35.91 ns | 0.6520 ns | 0.6099 ns |
| Aes192BitKeyExpansion | 47.13 ns | 0.7675 ns | 0.6804 ns |
| Aes256BitKeyExpansion | 42.32 ns | 0.9240 ns | 0.9887 ns |

## AES encrypt performance

|    Method | CipherMode | PaddingMode | KeySize | DataSize |            Mean |         Error |        StdDev | Ratio |
|---------- |----------- |------------ |-------- |--------- |----------------:|--------------:|--------------:|------:|
|     **AesNi** |        **CBC** |        **None** |     **128** |       **16** |        **54.14 ns** |     **0.1514 ns** |     **0.1416 ns** |  **0.66** |
| Framework |        CBC |        None |     128 |       16 |        81.48 ns |     0.4009 ns |     0.3554 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **128** |     **1024** |       **905.53 ns** |     **0.7135 ns** |     **0.6674 ns** |  **1.18** |
| Framework |        CBC |        None |     128 |     1024 |       769.19 ns |     2.2911 ns |     2.1431 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **128** |  **1048576** |   **860,640.48 ns** | **2,227.3371 ns** | **2,083.4525 ns** |  **1.15** |
| Framework |        CBC |        None |     128 |  1048576 |   750,397.90 ns |   790.3225 ns |   739.2682 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |       **16** |        **59.60 ns** |     **0.1091 ns** |     **0.0911 ns** |  **0.70** |
| Framework |        CBC |        None |     192 |       16 |        84.92 ns |     0.1918 ns |     0.1794 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |     **1024** |     **1,013.01 ns** |     **2.6764 ns** |     **2.5035 ns** |  **1.08** |
| Framework |        CBC |        None |     192 |     1024 |       935.30 ns |     2.6766 ns |     2.5037 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |  **1048576** | **1,017,828.74 ns** | **3,989.6438 ns** | **3,536.7153 ns** |  **1.14** |
| Framework |        CBC |        None |     192 |  1048576 |   891,961.83 ns | 1,076.3172 ns | 1,006.7878 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |       **16** |        **63.32 ns** |     **0.2041 ns** |     **0.1909 ns** |  **0.78** |
| Framework |        CBC |        None |     256 |       16 |        80.98 ns |     0.7079 ns |     0.6621 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |     **1024** |     **1,153.19 ns** |     **3.4437 ns** |     **3.0528 ns** |  **1.27** |
| Framework |        CBC |        None |     256 |     1024 |       907.08 ns |     2.1722 ns |     2.0318 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |  **1048576** | **1,167,788.83 ns** | **1,769.0211 ns** | **1,654.7434 ns** |  **1.31** |
| Framework |        CBC |        None |     256 |  1048576 |   893,367.08 ns | 1,135.6231 ns | 1,062.2626 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |       **16** |        **52.78 ns** |     **0.1274 ns** |     **0.1191 ns** |  **0.67** |
| Framework |        ECB |        None |     128 |       16 |        79.01 ns |     0.3803 ns |     0.3557 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |     **1024** |       **137.93 ns** |     **0.3078 ns** |     **0.2729 ns** |  **0.80** |
| Framework |        ECB |        None |     128 |     1024 |       173.33 ns |     0.4021 ns |     0.3762 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |  **1048576** |   **103,537.19 ns** |   **348.9570 ns** |   **326.4146 ns** |  **1.04** |
| Framework |        ECB |        None |     128 |  1048576 |    99,377.52 ns |   115.0458 ns |   107.6139 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **192** |       **16** |        **61.62 ns** |     **0.0697 ns** |     **0.0652 ns** |  **0.79** |
| Framework |        ECB |        None |     192 |       16 |        77.93 ns |     0.4503 ns |     0.4212 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **192** |     **1024** |       **163.30 ns** |     **0.4965 ns** |     **0.4402 ns** |  **0.84** |
| Framework |        ECB |        None |     192 |     1024 |       195.43 ns |     1.4095 ns |     1.3184 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **192** |  **1048576** |   **117,754.51 ns** |   **244.1254 ns** |   **228.3550 ns** |  **1.02** |
| Framework |        ECB |        None |     192 |  1048576 |   115,159.52 ns |   215.7692 ns |   201.8307 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **256** |       **16** |        **60.43 ns** |     **0.2084 ns** |     **0.1949 ns** |  **0.69** |
| Framework |        ECB |        None |     256 |       16 |        87.90 ns |     0.5672 ns |     0.5306 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **256** |     **1024** |       **187.20 ns** |     **0.2454 ns** |     **0.2296 ns** |  **0.93** |
| Framework |        ECB |        None |     256 |     1024 |       201.62 ns |     1.5318 ns |     1.4329 ns |  1.00 |
|           |            |             |         |          |                 |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **256** |  **1048576** |   **139,114.06 ns** |   **203.8322 ns** |   **190.6648 ns** |  **1.20** |
| Framework |        ECB |        None |     256 |  1048576 |   115,595.62 ns | 1,022.2509 ns |   956.2141 ns |  1.00 |

## AES decrypt performance

|    Method | CipherMode | PaddingMode | KeySize | DataSize |          Mean |         Error |        StdDev | Ratio |
|---------- |----------- |------------ |-------- |--------- |--------------:|--------------:|--------------:|------:|
|     **AesNi** |        **CBC** |        **None** |     **128** |       **16** |      **43.73 ns** |     **0.0535 ns** |     **0.0500 ns** |  **0.48** |
| Framework |        CBC |        None |     128 |       16 |      90.77 ns |     0.8170 ns |     0.7242 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **128** |     **1024** |     **145.47 ns** |     **1.0123 ns** |     **0.8453 ns** |  **0.75** |
| Framework |        CBC |        None |     128 |     1024 |     194.71 ns |     0.5619 ns |     0.4981 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **128** |  **1048576** | **113,914.12 ns** |   **140.6300 ns** |   **131.5454 ns** |  **1.01** |
| Framework |        CBC |        None |     128 |  1048576 | 113,073.21 ns |   414.6260 ns |   346.2315 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |       **16** |      **47.62 ns** |     **0.2948 ns** |     **0.2614 ns** |  **0.49** |
| Framework |        CBC |        None |     192 |       16 |      97.73 ns |     0.2251 ns |     0.1758 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |     **1024** |     **168.84 ns** |     **0.1239 ns** |     **0.1035 ns** |  **0.76** |
| Framework |        CBC |        None |     192 |     1024 |     223.52 ns |     1.4852 ns |     1.3892 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |  **1048576** | **130,108.49 ns** |   **161.2990 ns** |   **150.8791 ns** |  **0.98** |
| Framework |        CBC |        None |     192 |  1048576 | 132,629.49 ns |   341.9665 ns |   266.9849 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |       **16** |      **48.32 ns** |     **0.3912 ns** |     **0.3468 ns** |  **0.53** |
| Framework |        CBC |        None |     256 |       16 |      91.87 ns |     0.3842 ns |     0.3594 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |     **1024** |     **185.43 ns** |     **0.5482 ns** |     **0.5128 ns** |  **0.85** |
| Framework |        CBC |        None |     256 |     1024 |     217.41 ns |     0.8382 ns |     0.7430 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |  **1048576** | **152,047.83 ns** |   **815.8482 ns** |   **681.2702 ns** |  **1.16** |
| Framework |        CBC |        None |     256 |  1048576 | 131,606.89 ns |   313.9922 ns |   293.7085 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |       **16** |      **39.51 ns** |     **0.6943 ns** |     **0.6155 ns** |  **0.49** |
| Framework |        ECB |        None |     128 |       16 |      81.30 ns |     0.1341 ns |     0.1255 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |     **1024** |     **125.90 ns** |     **0.4105 ns** |     **0.3428 ns** |  **0.36** |
| Framework |        ECB |        None |     128 |     1024 |     346.04 ns |     3.7404 ns |     3.1234 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |  **1048576** | **102,197.59 ns** |   **675.1326 ns** |   **631.5194 ns** |  **0.39** |
| Framework |        ECB |        None |     128 |  1048576 | 261,232.28 ns | 3,116.7811 ns | 2,915.4390 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **192** |       **16** |      **44.97 ns** |     **0.3073 ns** |     **0.2874 ns** |  **0.54** |
| Framework |        ECB |        None |     192 |       16 |      82.58 ns |     0.2941 ns |     0.2751 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **192** |     **1024** |     **145.97 ns** |     **0.5833 ns** |     **0.4870 ns** |  **0.42** |
| Framework |        ECB |        None |     192 |     1024 |     349.21 ns |     0.5379 ns |     0.4768 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **192** |  **1048576** | **121,338.06 ns** | **1,527.1613 ns** | **1,428.5076 ns** |  **0.44** |
| Framework |        ECB |        None |     192 |  1048576 | 274,398.39 ns |   362.5910 ns |   339.1678 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **256** |       **16** |      **44.71 ns** |     **0.3569 ns** |     **0.3338 ns** |  **0.55** |
| Framework |        ECB |        None |     256 |       16 |      82.00 ns |     0.3009 ns |     0.2349 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **256** |     **1024** |     **162.33 ns** |     **0.7677 ns** |     **0.7181 ns** |  **0.47** |
| Framework |        ECB |        None |     256 |     1024 |     346.63 ns |     1.6859 ns |     1.5770 ns |  1.00 |
|           |            |             |         |          |               |               |               |       |
|     **AesNi** |        **ECB** |        **None** |     **256** |  **1048576** | **136,829.73 ns** |   **392.4239 ns** |   **306.3788 ns** |  **0.52** |
| Framework |        ECB |        None |     256 |  1048576 | 264,079.89 ns | 1,255.7255 ns | 1,174.6064 ns |  1.00 |
