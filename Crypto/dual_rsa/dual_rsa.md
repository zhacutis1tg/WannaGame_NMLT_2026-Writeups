# Challenge: dual_rsa
## Information
<img width="1127" height="309" alt="image" src="https://github.com/user-attachments/assets/7cdb72ad-5587-41ec-bf0f-59d0dcfcd9a1" />

## Solution
### Dữ liệu đề bài:
- $n = p \times q$
- $e = 65537$
- $hint = p \cdot e + q \cdot d$

### Xây dựng phương trình đạo hàm
Để giải quyết, ta cần đưa tất cả về cùng một ẩn số (chọn ẩn $q$).  
#### Bước 1: Biểu diễn $d$ qua $k$ 
Theo định nghĩa RSA:  

$$e \cdot d \equiv 1 \pmod{\phi(n)} \implies d = \frac{k\phi(n) + 1}{e}$$  

Trong đó $k$ là một số nguyên dương và $k < e$.  
#### Bước 2: Thay thế vào dữ kiện `hint`
$$hint = p \cdot e + q \cdot \left( \frac{k\phi(n) + 1}{e} \right)$$  
Nhân cả hai vế với $e$:  
$$e \cdot hint = p \cdot e^2 + q(k\phi(n) + 1)$$  
#### Bước 3: Chuyển đổi sang ẩn $q$
Biết rằng $p = n/q$ và $\phi(n) = n - p - q + 1$. Thay vào phương trình:  

$$e \cdot hint = \frac{n}{q} e^2 + q [k(n - \frac{n}{q} - q + 1) + 1]$$  

Nhân toàn bộ với $q$ để loại bỏ mẫu số:

$$q \cdot e \cdot hint = n e^2 + k q n - k n - k q^2 + k q + q$$  

#### Bước 4: Hình thành đa thức bậc 3
Sắp xếp các số hạng theo lũy thừa của $q$, ta thu được phương trình:  

$$f(q) = k \cdot q^3 - (kn + k + 1) \cdot q^2 + (kn + e \cdot hint) \cdot q - n e^2 = 0$$  
### Giải thuật
Vì $k < e$ ($e=65537$), ta có thể brute-force $k$ trong khoảng $[1, 65537]$.  
Với mỗi $k$, ta cần tìm nghiệm của phương trình bậc 3.  
- Sử dụng phương pháp Newton-Raphson để tìm nghiệm xấp xỉ số nguyên một cách cực nhanh thay vì dùng các hàm giải phương trình phức tạp.
- Hàm lặp: $x_{n+1} = x_n - \frac{f(x_n)}{f'(x_n)}$.
Khi tìm được $q$ là ước của $n$, tính $d$ và giải mã $c^d \pmod n$.

```python
import math

def solve():
    c = 519532614147274895343338282847612455024770925322967741876186772972688707464735548748114276855714088240613325903671184345763214563286596178351359418251471
    e = 65537
    n = 5525190662051722389398876030739412137775938774790992602567049718278780220882647212045017447852382983250859977157638406889457452433877216946759540980558617
    hint = 163390612248405216952422980053072618261066844986739856118768985945155558215222184475851962909161628806655516868219220339423593381547066084266538543418276501410521426782956172908562676847833099242113566651238300013430118494859297562

    for k in range(1, e):
        A = k*n + k + 1
        B = k*n + e*hint
        C = n*e*e
        
        delta = B**2 - 4*A*C
        if delta < 0: continue
        q_start = (B + math.isqrt(delta)) // (2*A)

        q = q_start
        for _ in range(10):
            f_q = k*q**3 - A*q**2 + B*q - C
            f_prime_q = 3*k*q**2 - 2*A*q + B
            if f_prime_q == 0: break
            q -= f_q // f_prime_q
        
        if q > 1 and n % q == 0:
            p = n // q
            d = pow(e, -1, (p-1)*(q-1))
            m = pow(c, d, n)
            print(f"Flag: {m.to_bytes((m.bit_length()+7)//8, 'big').decode()}")
            break

solve()
```
