# Fully managed .NET AES implementation (based on AES-NI) 

## AES ECB performance

``` ini

BenchmarkDotNet=v0.11.4, OS=Windows 10.0.17763.316 (1809/October2018Update/Redstone5)
AMD Ryzen Threadripper 1950X, 1 CPU, 32 logical and 16 physical cores
.NET Core SDK=3.0.100-preview3-010431
  [Host]     : .NET Core 3.0.0-preview3-27503-5 (CoreCLR 4.6.27422.72, CoreFX 4.7.19.12807), 64bit RyuJIT
  DefaultJob : .NET Core 3.0.0-preview3-27503-5 (CoreCLR 4.6.27422.72, CoreFX 4.7.19.12807), 64bit RyuJIT


```
|    Method | CipherMode | PaddingMode | KeySize | DataSize |          Mean |       Error |      StdDev | Ratio |
|---------- |----------- |------------ |-------- |--------- |--------------:|------------:|------------:|------:|
|     **AesNi** |        **ECB** |        **None** |     **128** |       **16** |      **29.08 ns** |   **0.1801 ns** |   **0.1684 ns** |  **0.36** |
| Framework |        ECB |        None |     128 |       16 |      80.44 ns |   0.5170 ns |   0.4318 ns |  1.00 |
|           |            |             |         |          |               |             |             |       |
|     **AesNi** |        **ECB** |        **None** |     **128** |     **1024** |     **114.91 ns** |   **0.2098 ns** |   **0.1962 ns** |  **0.65** |
| Framework |        ECB |        None |     128 |     1024 |     176.94 ns |   1.5947 ns |   1.4136 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **128** |  **1048576** | **102,859.72 ns** | **164.1943 ns** | **153.5874 ns** |  **1.03** |
| Framework |        ECB |        None |     128 |  1048576 |  99,542.88 ns | 450.8568 ns | 421.7318 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **192** |       **16** |      **33.05 ns** |   **0.1652 ns** |   **0.1545 ns** |  **0.41** |
| Framework |        ECB |        None |     192 |       16 |      80.05 ns |   0.3750 ns |   0.3507 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **192** |     **1024** |     **134.25 ns** |   **0.3663 ns** |   **0.3427 ns** |  **0.69** |
| Framework |        ECB |        None |     192 |     1024 |     195.86 ns |   0.3956 ns |   0.3700 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **192** |  **1048576** | **123,316.05 ns** | **268.5757 ns** | **251.2259 ns** |  **1.06** |
| Framework |        ECB |        None |     192 |  1048576 | 116,614.31 ns | 448.1315 ns | 397.2569 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **256** |       **16** |      **34.18 ns** |   **0.0915 ns** |   **0.0856 ns** |  **0.40** |
| Framework |        ECB |        None |     256 |       16 |      86.10 ns |   0.5093 ns |   0.4764 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **256** |     **1024** |     **154.63 ns** |   **1.1072 ns** |   **0.9245 ns** |  **0.78** |
| Framework |        ECB |        None |     256 |     1024 |     199.32 ns |   2.0586 ns |   1.8249 ns |  1.00 |        
|           |            |             |         |          |               |             |             |       |        
|     **AesNi** |        **ECB** |        **None** |     **256** |  **1048576** | **136,568.43 ns** | **357.7535 ns** | **317.1392 ns** |  **1.18** |
| Framework |        ECB |        None |     256 |  1048576 | 116,104.49 ns | 436.8765 ns | 387.2796 ns |  1.00 |        

# AES CBC performance

``` ini

BenchmarkDotNet=v0.11.4, OS=macOS Mojave 10.14.3 (18D109) [Darwin 18.2.0]
Intel Core i7-6660U CPU 2.40GHz (Skylake), 1 CPU, 4 logical and 2 physical cores
.NET Core SDK=3.0.100-preview3-010431
  [Host]     : .NET Core 3.0.0-preview3-27503-5 (CoreCLR 4.6.27422.72, CoreFX 4.7.19.12807), 64bit RyuJIT
  DefaultJob : .NET Core 3.0.0-preview3-27503-5 (CoreCLR 4.6.27422.72, CoreFX 4.7.19.12807), 64bit RyuJIT


```
|    Method | CipherMode | PaddingMode | KeySize | DataSize |            Mean |          Error |         StdDev | Ratio |
|---------- |----------- |------------ |-------- |--------- |----------------:|---------------:|---------------:|------:|
|     **AesNi** |        **CBC** |        **None** |     **128** |       **16** |        **27.80 ns** |      **0.1622 ns** |      **0.1438 ns** |  **0.29** |
| Framework |        CBC |        None |     128 |       16 |        96.98 ns |      0.2502 ns |      0.2218 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **128** |     **1024** |       **863.73 ns** |      **5.3032 ns** |      **4.9606 ns** |  **0.94** |
| Framework |        CBC |        None |     128 |     1024 |       918.40 ns |      2.1949 ns |      1.9457 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **128** |  **1048576** |   **854,703.59 ns** |  **3,005.0224 ns** |  **2,663.8741 ns** |  **0.99** |
| Framework |        CBC |        None |     128 |  1048576 |   863,260.85 ns |  2,828.2718 ns |  2,645.5672 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |       **16** |        **35.11 ns** |      **0.2183 ns** |      **0.2042 ns** |  **0.36** |
| Framework |        CBC |        None |     192 |       16 |        96.48 ns |      0.6304 ns |      0.5264 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |     **1024** |     **1,011.62 ns** |      **4.2406 ns** |      **3.9666 ns** |  **0.94** |
| Framework |        CBC |        None |     192 |     1024 |     1,074.59 ns |      2.8749 ns |      2.2445 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **192** |  **1048576** | **1,015,169.18 ns** |  **4,012.1060 ns** |  **3,556.6275 ns** |  **1.00** |
| Framework |        CBC |        None |     192 |  1048576 | 1,018,285.19 ns |  3,399.0243 ns |  2,838.3392 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |       **16** |        **33.46 ns** |      **0.1692 ns** |      **0.1413 ns** |  **0.35** |
| Framework |        CBC |        None |     256 |       16 |        96.79 ns |      1.4732 ns |      1.2302 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |     **1024** |     **1,168.55 ns** |      **3.6966 ns** |      **3.2769 ns** |  **1.09** |
| Framework |        CBC |        None |     256 |     1024 |     1,074.79 ns |      5.0793 ns |      4.5027 ns |  1.00 |
|           |            |             |         |          |                 |                |                |       |
|     **AesNi** |        **CBC** |        **None** |     **256** |  **1048576** | **1,182,163.55 ns** | **14,077.5401 ns** | **10,990.8173 ns** |  **1.16** |
| Framework |        CBC |        None |     256 |  1048576 | 1,020,059.05 ns |  6,386.6060 ns |  5,974.0352 ns |  1.00 |
