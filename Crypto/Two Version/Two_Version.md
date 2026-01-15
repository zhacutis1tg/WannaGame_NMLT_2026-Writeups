# Challenge: Two Version
## Information
<img width="1118" height="288" alt="image" src="https://github.com/user-attachments/assets/9ee2d71e-e953-44b4-bd99-795f9a84fb77" />

## Solution
Hệ thống sử dụng một mô hình mã hóa RSA hai lớp (Nested RSA) để bảo vệ khóa AES.
- Plaintext: Flag.
- AES Key: `secret` (16 bytes).
- Lớp 1 (Inner): $hint = secret^e \pmod{N_1}$. Với $e = e_0 + k \cdot \phi_1$.
- Lớp 2 (Outer): $ct = hint^{65537} \pmod{N_2}$. Với $N_2$ là tích của 17 số nguyên tố liên tiếp.

### Bước 1: Tấn công lớp RSA ngoài ($N_2$)
#### Lỗ hổng: Thừa số nguyên tố quá gần nhau
Thông thường, RSA an toàn vì việc phân tích $N$ thành các số nguyên tố rất khó.  
Tuy nhiên, ở đây $N_2$ được tạo ra bằng cách lấy một số nguyên tố 128-bit ngẫu nhiên, sau đó lấy 16 số nguyên tố kế tiếp nó 

$$N_2 = p_1 \times p_2 \times \dots \times p_{17}$$

Vì các số nguyên tố này nằm sát nhau trên trục số, chúng sẽ hội tụ quanh giá trị căn bậc 17 của $N_2$:

$$p_i \approx \sqrt[17]{N_2}$$

#### Cách khai thác
- Sử dụng hàm `integer_nthroot(N2, 17)` để tìm giá trị xấp xỉ $r$.
- Duyệt các số lẻ xung quanh $r$. Với mỗi số, kiểm tra xem nó có phải là ước của $N_2$ không.
- Khi tìm thấy một ước, ta dễ dàng tìm được 16 ước còn lại bằng hàm `next_prime` hoặc `prev_prime`.
- Khi đó:
  - $\phi_2 = (p_1-1)(p_2-1)\dots(p_{17}-1)$
  - $d_2 = \text{inverse}(65537, \phi_2)$
  - $hint = ct^{d_2} \pmod{N_2}$
 
### Bước 2: Tấn công lớp RSA trong ($N_1$)
#### Lỗ hổng: Số mũ $e$ cực lớn và tính chất Định lý Euler
Thông thường $e$ chỉ khoảng 65537, nhưng ở đây $e$ lớn hơn cả $N_1$.  
Theo đề bài:

$e = e_0 + (k \cdot \phi_1)$

Trong đó $e_0$ là `getPrime(32)` và $k$ là `bytes_to_long(os.urandom(32))`.  
Dựa trên Định lý Euler: $m^{\phi(N)} \equiv 1 \pmod N$. Ta có:

$$secret^e \equiv secret^{e_0 + k \cdot \phi_1} \equiv secret^{e_0} \cdot (secret^{\phi_1})^k \equiv secret^{e_0} \cdot 1^k \equiv secret^{e_0} \pmod{N_1}$$

Vậy thực chất, số mũ hiệu dụng chỉ là $e_0$ (32 bit).  

#### Cách khai thác
- Vì $e_0$ rất nhỏ (32-bit), ta có $e \approx k \cdot \phi_1$. Mà $\phi_1 \approx N_1$.

$$\implies k \approx \lfloor \frac{e}{N_1} \rfloor$$

- Khôi phục $\phi_1$:
  - Thực hiện phép chia: $k = (e + N_1 - 1) // N_1$
  - $\phi_1 = e // k$
  - $e_0 = e \pmod k$ (hoặc $e \pmod{\phi_1}$)
- Để chắc chắn $\phi_1$ đúng, ta giải hệ tìm $p, q$ của $N_1$:
  - $S = p + q = N_1 - \phi_1 + 1$
  - Giải phương trình bậc 2: $x^2 - Sx + N_1 = 0$. Nếu tìm được nghiệm nguyên $p, q$ thì $\phi_1$ chuẩn xác.

### Bước 3: Giải mã AES
Sau khi có $hint$, $e_0$, và $\phi_1$:
- Tính số mũ giải mã: $d_{inner} = \text{inverse}(e_0, \phi_1)$.
- Tìm `secret`: $secret = hint^{d_{inner}} \pmod{N_1}$.
- Chuyển `secret` thành chuỗi bytes (16 bytes).
- Sử dụng `AES.MODE_ECB` để giải mã `enc_flag`.


```python
from Crypto.Util.number import inverse, long_to_bytes, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from math import isqrt, prod
from sympy import integer_nthroot, nextprime, prevprime

N1 = 17362209236509579956069121909745118765799063323981053744694079912565491761665470166232725041911668984587357851108379264256444768723119405696823379326603919936432028254892304111890799155248313945504362228086008054153337335473581045441412224034029131473052839257492200434841614255071621144691873145779936936466540564808189303815230586143579770974537663138227520239222958954087051769031139540550385941998442389661281975075970676604559169389854098177253292054675455122805187979417072249915003812124619547817345238821993663526288499599335194728734483790328454191490869993428411439760162813987746438088527227601749820028193
e = 568582705727074893855912262854931693776520061370825795622408975722616647195254499204299022659637745471845846557420791526279013376743846402285643895966976225319567903776419747592534878785237707018847064329521965900069329553901759652438404357571363572446084085687887505441095248254418448399269726503670730040360740992133710023103279528719378138713561929468837511729721619671738503296388639260766495550559585215630589053151303089778450120428975766990144168252012620202718975328284160837828555307103092360072925443331146944544205083563459507313906353592377402822356714725646404116880466954160143406854279706045105410824643858602601732293803652038686291057500387221541409697375265891315799717338405
N2 = 174553024057014543990096002679862638088905851653879673222226052298055708844181812197941875851675416263226641449259760427101268268472069203586567587515794891047875245725162110718082616270544366434288997011409037775968719808654349176938207119625705703790242080128391560864432915193871137643173668518980792686437123926377623591683827956931115090648091374719966673705080651380216030247495007008029626444956423886177383838787824634354346012965466030223117377462983842249633655418289489207513555281526739138705675027976815421110574047635449979101326595680755121900431939859745287285869554512425317799105125963506050787144028639637446623602111823871042061393
ct = 132963375508750110982747240401551817429093402914130496323529445591699573319732182982477592602548638283213896716757534905217268537453949332314065417291803810569772825403916533444924533708208557973427355332410755739881415766694571930525562269127527531894626120363166965760452473821975744785213257372447726685728346094300092678082137396501264318071662127385515962532743128346914780190335936819653183800050104005846840953382428383415290230446004794710008750774068731703819552901643139934566602333045031459877867709818046467532841903296594824234648604109806308639955400969917946294822261213855069675091607810871889832057748335243982627101739006805995485773
enc_flag = b'\xe23\x8c\x89~\xce\\\x10\x85\xa7\x92)\x17zPu\x17Ny1\x82\x1a\xf4\x1bS\xa8\xcb\xe2\xb7\xf4\x07\x84\x93\xe6{\xc308\x94\xd0\xcfg\x96\xf2\x8dd\xa4"'

def find_prime_factor(n, start_val, limit=10000):
    hi, lo = nextprime(start_val), prevprime(start_val)
    for _ in range(limit):
        if n % hi == 0: return int(hi)
        if n % lo == 0: return int(lo)
        hi, lo = nextprime(hi), prevprime(lo)
    return None

def get_consecutive_factors(n, known_factor):
    factors = [known_factor]
    curr = known_factor
    while True:
        curr = int(prevprime(curr))
        if n % curr == 0: factors.append(curr)
        else: break
    curr = known_factor
    while True:
        curr = int(nextprime(curr))
        if n % curr == 0: factors.append(curr)
        else: break
    return sorted(factors)


num_factors = 17
approx_root, _ = integer_nthroot(N2, num_factors)
seed_factor = find_prime_factor(N2, int(approx_root))

all_factors = get_consecutive_factors(N2, seed_factor)
assert prod(all_factors) == N2

phi2 = prod(p - 1 for p in all_factors)
d_outer = inverse(0x10001, phi2)
hint = pow(ct, d_outer, N2)


k = (e + N1 - 1) // N1
phi1 = e // k
e_inner = e % k


sum_pq = N1 - phi1 + 1
delta = sum_pq**2 - 4 * N1
delta_sqrt = isqrt(delta)
assert delta_sqrt**2 == delta

p = (sum_pq + delta_sqrt) // 2
q = (sum_pq - delta_sqrt) // 2
assert p * q == N1


d_inner = inverse(e_inner, phi1)
secret_val = pow(hint, d_inner, N1)
aes_key = long_to_bytes(secret_val, 16)


cipher = AES.new(aes_key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(enc_flag), 16)

print(f"Flag: {flag.decode()}")
```

<img width="542" height="52" alt="image" src="https://github.com/user-attachments/assets/60ede5e1-a664-48e4-a21f-5b48e5b5bd7f" />

