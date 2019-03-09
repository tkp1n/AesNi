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
