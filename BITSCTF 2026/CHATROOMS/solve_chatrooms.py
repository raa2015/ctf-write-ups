#!/usr/bin/env python3
"""
==============================================================================
ChatRooms CTF - Exploit Completo (Rooms 1-3)
==============================================================================

Resuelve automaticamente las 3 salas del reto ChatRooms explotando
vulnerabilidades en la generacion de nonces ECDSA:

  Room 1: Alpha_01    - Nonce constante (k = 0xDEADC0DE)
  Room 2: Exarch_01   - Nonce LCG (k2 = A*k1 + B) con parametros de Rachel
  Room 3: Cracked_Core - Recurrencia polinomial grado 2 (Polynonce attack)

Flag: BITSCTF{3CD54_n0nc3_n0nc3nc3_676767}

Uso:
    source venv/bin/activate
    python3 solve_chatrooms.py

Dependencias:
    pip install ecdsa
"""

import socket
import time
import re
import hashlib
import itertools
import random
from ecdsa import SECP256k1

# ==============================================================================
# Configuracion
# ==============================================================================

HOST = "20.193.149.152"
PORT = 1342

# Curva SECP256k1
N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
G = SECP256k1.generator

# Room 1: Alpha_01 usa nonce constante k = 0xDEADC0DE
# Como k es constante, r = (k*G).x tambien es constante:
R_ALPHA = int("20b964ead5037915921e2887a069a08fb57e1213c1c11d0b7e230aff96e9456f", 16)
K_ALPHA = 0xDEADC0DE

# Regex para limpiar codigos ANSI del terminal
ANSI_RE = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]")


# ==============================================================================
# Funcion de hash
# ==============================================================================

def H(msg):
    """SHA-256 del mensaje, convertido a entero mod N"""
    return int.from_bytes(hashlib.sha256(msg.encode()).digest(), "big") % N


# ==============================================================================
# ROOM 1: Nonce constante k = 0xDEADC0DE
# ==============================================================================
# Alpha_01 firma todos sus mensajes con el mismo nonce k = 0xDEADC0DE.
# Esto produce siempre el mismo valor r (= coordenada x de k*G).
#
# De la ecuacion ECDSA:  s = k^{-1} * (z + r*d)  mod N
# Despejamos:            d = (s*k - z) * r^{-1}   mod N
#
# Con k conocido, una sola firma basta para recuperar d.

def solve_room1(msg, s_hex):
    """
    Recupera la clave privada de Alpha_01.

    Args:
        msg:   Texto del mensaje firmado
        s_hex: Componente s de la firma (hex string "0x...")

    Returns:
        d: Clave privada (entero)
    """
    z = H(msg)                                          # Hash del mensaje
    s = int(s_hex, 16) % N                              # Componente s de la firma
    d = ((s * K_ALPHA - z) % N) * pow(R_ALPHA, -1, N) % N  # d = (s*k - z) / r
    return d


# ==============================================================================
# ROOM 2: Nonce LCG  k2 = A*k1 + B  mod N
# ==============================================================================
# Exarch_01 genera nonces usando un LCG (Linear Congruential Generator).
# Los parametros A y B se obtienen de los mensajes de Rachel_Relay.
#
# Rachel envia 8 pares de fragmentos hexadecimales de 32 bits cada uno:
#   A_CHUNK:1a2b3c4d | B_CHUNK:5e6f7a8b
#
# Concatenando los 8 A_CHUNKs = multiplicador A (256 bits)
# Concatenando los 8 B_CHUNKs = sumando B (256 bits)
#
# Con 2 firmas de Exarch_01 y la relacion k2 = A*k1 + B:
#   (z2+r2*d)/s2 = A*(z1+r1*d)/s1 + B
# Se resuelve para d.

def concat_chunks(pairs, key):
    """
    Concatena los fragmentos hex de Rachel para formar un numero de 256 bits.

    Args:
        pairs: Lista de diccionarios con claves "a" y "b"
        key:   "a" para A_CHUNKs, "b" para B_CHUNKs

    Returns:
        Entero de 256 bits mod N
    """
    return int("".join(p[key] for p in pairs), 16) % N


def solve_room2(ex1, ex2, A, B):
    """
    Recupera la clave privada de Exarch_01 via LCG.

    La relacion entre nonces es:  k2 = A * k1 + B  mod N

    De ECDSA:  k_i = (z_i + r_i * d) * s_i^{-1}

    Sustituyendo en la relacion LCG y despejando d:
        d = (A*z1/s1 - z2/s2 + B) / (r2/s2 - A*r1/s1)  mod N

    Args:
        ex1, ex2: Diccionarios con claves "msg", "r", "s" (firmas de Exarch_01)
        A:        Multiplicador LCG (entero)
        B:        Sumando LCG (entero)

    Returns:
        d: Clave privada, o None si la solucion es invalida
    """
    r1, s1, z1 = int(ex1["r"], 16) % N, int(ex1["s"], 16) % N, H(ex1["msg"])
    r2, s2, z2 = int(ex2["r"], 16) % N, int(ex2["s"], 16) % N, H(ex2["msg"])

    invs1 = pow(s1, -1, N)    # s1^{-1} mod N
    invs2 = pow(s2, -1, N)    # s2^{-1} mod N

    # Coeficiente de d en la ecuacion
    coef = (r2 * invs2 - A * r1 * invs1) % N
    if coef == 0:
        return None  # Sistema degenerado

    # Lado derecho de la ecuacion
    rhs = (A * z1 * invs1 - z2 * invs2 + B) % N

    # Resolver para d
    d = (rhs * pow(coef, -1, N)) % N

    # Verificar que los nonces cumplen la relacion LCG
    k1 = ((z1 + r1 * d) * invs1) % N
    k2 = ((z2 + r2 * d) * invs2) % N
    if (k2 - (A * k1 + B)) % N != 0:
        return None  # Verificacion fallida

    return d


# ==============================================================================
# ROOM 3: Recurrencia polinomial de grado 2 (Polynonce Attack)
# ==============================================================================
# Cracked_Core genera nonces con una recurrencia cuadratica:
#   k_{i+1} = a * k_i^2 + b * k_i + c   mod N
#
# Esto NO es lo mismo que un nonce polinomial en el indice (k_i = f(i)).
# Es una recurrencia donde cada nonce depende del anterior.
#
# Con 5 firmas, podemos eliminar los coeficientes desconocidos a, b, c
# y obtener una ecuacion polinomial de grado 4 en la incognita d.
#
# Las raices de este polinomio se encuentran usando el algoritmo de
# Cantor-Zassenhaus sobre GF(N).
#
# Como no conocemos el orden de los nonces, probamos las 120 permutaciones
# de las 5 firmas.


# --- Aritmetica de polinomios sobre GF(N) ---
#
# Un polinomio se representa como lista de coeficientes:
#   [c0, c1, c2, ...] = c0 + c1*x + c2*x^2 + ...
# Todas las operaciones son mod N (aritmetica en campo finito).

def poly_strip(p):
    """Elimina coeficientes cero al final del polinomio."""
    while len(p) > 1 and p[-1] == 0:
        p = p[:-1]
    return p


def poly_add(a, b):
    """Suma de polinomios: a(x) + b(x) mod N"""
    n = max(len(a), len(b))
    result = [0] * n
    for i in range(len(a)):
        result[i] = (result[i] + a[i]) % N
    for i in range(len(b)):
        result[i] = (result[i] + b[i]) % N
    return poly_strip(result)


def poly_sub(a, b):
    """Resta de polinomios: a(x) - b(x) mod N"""
    n = max(len(a), len(b))
    result = [0] * n
    for i in range(len(a)):
        result[i] = (result[i] + a[i]) % N
    for i in range(len(b)):
        result[i] = (result[i] - b[i]) % N
    return poly_strip(result)


def poly_mul(a, b):
    """Multiplicacion de polinomios: a(x) * b(x) mod N"""
    if len(a) == 0 or len(b) == 0:
        return [0]
    result = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        for j in range(len(b)):
            result[i + j] = (result[i + j] + a[i] * b[j]) % N
    return poly_strip(result)


def poly_mod(a, b):
    """
    Residuo polinomial: a(x) mod b(x).
    Usa division larga de polinomios sobre GF(N).
    """
    a = list(a)
    while len(a) >= len(b) and any(x != 0 for x in a):
        if a[-1] == 0:
            a.pop()
            continue
        coeff = (a[-1] * pow(b[-1], -1, N)) % N
        shift = len(a) - len(b)
        for i in range(len(b)):
            a[shift + i] = (a[shift + i] - coeff * b[i]) % N
        while len(a) > 1 and a[-1] == 0:
            a.pop()
    return a


def poly_gcd(a, b):
    """
    GCD de polinomios sobre GF(N) usando el algoritmo de Euclides.
    Devuelve un polinomio monico (coeficiente lider = 1).
    """
    while b != [0] and any(x != 0 for x in b):
        a, b = b, poly_mod(a, b)
    # Hacer monico: dividir por el coeficiente lider
    if len(a) > 0 and a[-1] != 0:
        inv = pow(a[-1], -1, N)
        a = [(x * inv) % N for x in a]
    return a


def poly_powmod(base, exp, modpoly):
    """
    Exponenciacion modular de polinomios: base(x)^exp mod modpoly(x).

    Usa square-and-multiply. Como N tiene ~256 bits, esto requiere
    ~256 iteraciones. Los polinomios intermedios siempre se reducen
    mod modpoly, manteniendo el grado acotado.
    """
    result = [1]  # Polinomio constante 1
    base = poly_mod(base, modpoly)
    while exp > 0:
        if exp & 1:
            result = poly_mod(poly_mul(result, base), modpoly)
        base = poly_mod(poly_mul(base, base), modpoly)
        exp >>= 1
    return result


def poly_roots(f):
    """
    Encuentra todas las raices de f(x) en GF(N) usando Cantor-Zassenhaus.

    Algoritmo:
    1. Calcular g = gcd(f, x^N - x).  En GF(N), x^N - x = prod(x - a) para
       todo a en GF(N). Asi que g es el producto de los factores lineales de f.
    2. Si g tiene grado > 1, factorizar usando Cantor-Zassenhaus:
       - Elegir r aleatorio, calcular gcd(g, (x+r)^{(N-1)/2} - 1)
       - Esto separa ~mitad de las raices (por criterio de Euler)
       - Repetir recursivamente
    3. Extraer raices de los factores lineales.

    Args:
        f: Polinomio (lista de coeficientes)

    Returns:
        Lista de raices (enteros mod N)
    """
    f = poly_strip(f)

    # Caso base: grado 0 -> sin raices
    if len(f) <= 1:
        return []

    # Caso base: grado 1 -> raiz directa
    # c0 + c1*x = 0  =>  x = -c0 * c1^{-1}
    if len(f) == 2:
        return [((-f[0]) * pow(f[1], -1, N)) % N]

    # Paso 1: Encontrar la parte separable (producto de factores lineales)
    # gcd(f, x^N - x) da exactamente los factores lineales de f
    xpoly = [0, 1]  # Polinomio "x"
    xN = poly_powmod(xpoly, N, f)       # x^N mod f
    xN_minus_x = poly_sub(xN, xpoly)    # x^N - x mod f
    g = poly_gcd(f, xN_minus_x)
    g = poly_strip(g)

    # Si gcd tiene grado 0, f no tiene raices en GF(N)
    if len(g) <= 1:
        return []

    # Si gcd es lineal, una sola raiz
    if len(g) == 2:
        return [((-g[0]) * pow(g[1], -1, N)) % N]

    # Paso 2: Cantor-Zassenhaus para factorizar g
    roots = []
    stack = [g]
    attempts = 0

    while stack and attempts < 200:
        h = stack.pop()

        # Factor lineal -> extraer raiz directamente
        if len(h) == 2:
            roots.append(((-h[0]) * pow(h[1], -1, N)) % N)
            continue
        if len(h) <= 1:
            continue

        # Elegir r aleatorio y calcular gcd(h, (x+r)^{(N-1)/2} - 1)
        # Por el criterio de Euler, (x+r)^{(N-1)/2} = +1 o -1 para cada raiz.
        # Esto divide las raices en ~dos mitades.
        r = random.randint(1, N - 1)
        rp = [r, 1]  # Polinomio r + x
        rp_exp = poly_powmod(rp, (N - 1) // 2, h)
        rp_exp_minus1 = poly_sub(rp_exp, [1])
        factor = poly_gcd(h, rp_exp_minus1)
        factor = poly_strip(factor)

        if len(factor) > 1 and len(factor) < len(h):
            # Factorizacion exitosa: dos factores no triviales
            stack.append(factor)
            # El otro factor viene de gcd(h, (x+r)^{(N-1)/2} + 1)
            rp_exp_plus1 = poly_add(rp_exp, [1])
            factor2 = poly_gcd(h, rp_exp_plus1)
            factor2 = poly_strip(factor2)
            if len(factor2) > 1:
                stack.append(factor2)
        else:
            # r no separo las raices, reintentar con otro r
            stack.append(h)
        attempts += 1

    return roots


def verify_key(d, sig):
    """
    Verifica que d sea la clave privada correcta para una firma dada.

    Recupera el nonce k a partir de d y la firma, luego verifica que
    k*G tenga la coordenada x correcta (= r de la firma).

    Args:
        d:   Clave privada candidata (entero)
        sig: Diccionario con claves "msg", "r", "s"

    Returns:
        True si d es valida
    """
    r = int(sig['r'], 16) % N
    s = int(sig['s'], 16) % N
    z = H(sig['msg'])
    k = ((z + r * d) * pow(s, -1, N)) % N
    if k == 0:
        return False
    try:
        return (k * G).x() % N == r
    except Exception:
        return False


def attack_degree1(sigs_ordered):
    """
    Ataque LCG (recurrencia de grado 1): k_{i+1} = a*k_i + b.
    Necesita 4 firmas en orden.

    Cada k_i es lineal en d:
        k_i = alpha_i + beta_i * d

    Las diferencias delta_i = k_{i+1} - k_i tambien son lineales en d.

    Para LCG: delta_{i+1} / delta_i = a (constante)
    Equivalentemente: delta_1^2 - delta_0 * delta_2 = 0

    Esto da un polinomio de grado 2 en d.

    Args:
        sigs_ordered: Lista de 4 firmas en el orden de la recurrencia

    Returns:
        Lista de raices (claves candidatas)
    """
    if len(sigs_ordered) < 4:
        return []

    # Representar k_i como polinomio lineal en d: [alpha_i, beta_i]
    polys = []
    for sig in sigs_ordered[:4]:
        r = int(sig['r'], 16) % N
        s = int(sig['s'], 16) % N
        z = H(sig['msg'])
        S = pow(s, -1, N)
        # k_i = z/s + (r/s)*d  =  [z*S, r*S]
        polys.append([(z * S) % N, (r * S) % N])

    # delta_i = k_{i+1} - k_i (polinomio de grado 1 en d)
    deltas = [poly_sub(polys[i + 1], polys[i]) for i in range(3)]

    # Ecuacion: delta_1^2 - delta_0 * delta_2 = 0 (grado 2 en d)
    eq = poly_sub(
        poly_mul(deltas[1], deltas[1]),
        poly_mul(deltas[0], deltas[2])
    )
    eq = poly_strip(eq)

    if all(c == 0 for c in eq):
        return []  # Ecuacion trivialmente satisfecha (degenerado)

    return poly_roots(eq)


def attack_degree2(sigs_ordered):
    """
    Ataque de recurrencia cuadratica: k_{i+1} = a*k_i^2 + b*k_i + c.
    Necesita 5 firmas en orden.

    Derivacion:
    -----------
    Para f(x) = ax^2 + bx + c, se cumple:
        f(k_{i+1}) - f(k_i) = (k_{i+1} - k_i) * [a*(k_{i+1} + k_i) + b]

    Es decir:
        delta_{i+1} = delta_i * (a * sigma_i + b)

    Donde:
        delta_i = k_{i+1} - k_i
        sigma_i = k_{i+1} + k_i

    Tres ecuaciones (i=0,1,2):
        delta_1/delta_0 = a*sigma_0 + b    ... (P0)
        delta_2/delta_1 = a*sigma_1 + b    ... (P1)
        delta_3/delta_2 = a*sigma_2 + b    ... (P2)

    Restando P0-P1 y P1-P2, y haciendo cociente para eliminar a:
        (delta_1/delta_0 - delta_2/delta_1)(sigma_1-sigma_2) =
        (delta_2/delta_1 - delta_3/delta_2)(sigma_0-sigma_1)

    Multiplicando por delta_0*delta_1*delta_2:
        (delta_1^2 - delta_0*delta_2) * delta_2 * (sigma_1-sigma_2) =
        (delta_2^2 - delta_1*delta_3) * delta_0 * (sigma_0-sigma_1)

    Como cada delta y sigma es de grado 1 en d, la ecuacion
    resultante es de grado 4 en d.

    Args:
        sigs_ordered: Lista de 5 firmas en el orden de la recurrencia

    Returns:
        Lista de raices (claves candidatas)
    """
    if len(sigs_ordered) < 5:
        return []

    # Representar k_i como polinomio lineal en d
    polys = []
    for sig in sigs_ordered[:5]:
        r = int(sig['r'], 16) % N
        s = int(sig['s'], 16) % N
        z = H(sig['msg'])
        S = pow(s, -1, N)
        polys.append([(z * S) % N, (r * S) % N])

    # delta_i = k_{i+1} - k_i  (grado 1 en d)
    deltas = [poly_sub(polys[i + 1], polys[i]) for i in range(4)]

    # sigma_i = k_i + k_{i+1}  (grado 1 en d)
    sigmas = [poly_add(polys[i], polys[i + 1]) for i in range(4)]

    # Lado izquierdo (LHS):
    # (delta_1^2 - delta_0*delta_2) * delta_2 * (sigma_1 - sigma_2)
    LHS = poly_mul(
        poly_sub(poly_mul(deltas[1], deltas[1]),
                 poly_mul(deltas[0], deltas[2])),
        poly_mul(deltas[2],
                 poly_sub(sigmas[1], sigmas[2]))
    )

    # Lado derecho (RHS):
    # (delta_2^2 - delta_1*delta_3) * delta_0 * (sigma_0 - sigma_1)
    RHS = poly_mul(
        poly_sub(poly_mul(deltas[2], deltas[2]),
                 poly_mul(deltas[1], deltas[3])),
        poly_mul(deltas[0],
                 poly_sub(sigmas[0], sigmas[1]))
    )

    # Ecuacion: LHS - RHS = 0 (grado 4 en d)
    eq = poly_sub(LHS, RHS)
    eq = poly_strip(eq)

    if all(c == 0 for c in eq):
        return []

    return poly_roots(eq)


# ==============================================================================
# Comunicacion con el servidor
# ==============================================================================

def connect():
    """Establece conexion TCP con el servidor del reto."""
    s = socket.create_connection((HOST, PORT), timeout=15)
    s.settimeout(0.5)
    return s


# ==============================================================================
# Exploit principal
# ==============================================================================

def main():
    sock = connect()
    buf = b""

    # Estado del parser
    last_user = None   # Ultimo usuario que envio mensaje
    last_msg = None    # Ultimo mensaje recibido

    # Estado de progreso
    room = 1           # Sala actual (1, 1.5, 2, 3, 4)

    # --- Room 1 ---
    d1 = None          # Clave privada de Alpha_01

    # --- Room 2 ---
    d2 = None          # Clave privada de Exarch_01
    exarch = []        # Firmas recolectadas de Exarch_01 (max 2)
    relay_pairs = []   # Pares A_CHUNK/B_CHUNK de Rachel (max 8)
    seen_relay = set() # Para evitar duplicados

    # --- Room 3 ---
    r3_sigs = []       # Firmas unicas de Cracked_Core
    r3_seen = set()    # Para evitar duplicados (r, s)
    r3_submitted = False  # Ya se envio la clave?

    # Control de timing
    next_tick = time.time() + 0.5
    started = time.time()

    print("[*] Conectado al servidor", flush=True)
    print(f"[*] Target: {HOST}:{PORT}", flush=True)

    try:
        while time.time() - started < 300:  # Timeout global de 5 minutos

            # ---- Enviar @boss periodicamente ----
            if time.time() >= next_tick:
                try:
                    sock.sendall(b"@boss\n")
                except Exception:
                    break
                # Mas rapido en rooms tempranos, mas lento en room 3
                next_tick = time.time() + (0.5 if room < 3 else 0.8)

            # ---- Recibir datos ----
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                continue
            if not chunk:
                break

            # ---- Parsear linea por linea ----
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                # Limpiar codigos ANSI y retornos de carro
                line = ANSI_RE.sub(b"", line).replace(b"\r", b"")
                txt = line.decode("utf-8", "ignore").strip()
                if not txt:
                    continue
                low = txt.lower()

                # ---- Deteccion de flag ----
                if "bitsctf{" in low:
                    print(f"\n{'='*60}", flush=True)
                    print(f"*** FLAG: {txt}", flush=True)
                    print(f"{'='*60}", flush=True)
                    return

                # ---- Deteccion de avance de sala ----
                if "[system]: room 1 key validated" in low:
                    room = 2
                    print("[+] Room 1 resuelto -> Entrando a Room 2", flush=True)

                if "[system]: room 2 key validated" in low:
                    room = 3
                    print("[+] Room 2 resuelto -> Entrando a Room 3!", flush=True)

                if "[system]: room 3 key validated" in low:
                    room = 4
                    print("[+] Room 3 resuelto -> Entrando a Room 4!!", flush=True)
                    # Esperar a recibir la flag
                    time.sleep(3)
                    try:
                        final = sock.recv(65536).decode(errors='replace')
                        print(final, flush=True)
                    except Exception:
                        pass
                    return

                if "*** vault open ***" in low:
                    print("[+] VAULT ABIERTO!", flush=True)

                # ---- Parsear mensaje de usuario ----
                # Formato: [USUARIO]: texto  o  User: [USUARIO]: texto
                m_msg = re.match(r"^(?:User:\s*)?\[(\w+)\]:\s*(.*)$", txt)
                if m_msg and not txt.startswith("Sig:"):
                    last_user = m_msg.group(1)
                    last_msg = m_msg.group(2)

                    # Room 2: Recolectar chunks de Rachel_Relay
                    if room == 2 and last_user == "Rachel_Relay":
                        cm = re.search(
                            r"A_CHUNK:([0-9a-fA-F]{8})\s*\|\s*B_CHUNK:([0-9a-fA-F]{8})",
                            last_msg
                        )
                        if cm:
                            a, b = cm.group(1).lower(), cm.group(2).lower()
                            if (a, b) not in seen_relay and len(relay_pairs) < 8:
                                seen_relay.add((a, b))
                                relay_pairs.append({"a": a, "b": b})
                                print(f"  [Rachel] Chunk #{len(relay_pairs)}/8: "
                                      f"A={a} B={b}", flush=True)
                    continue

                # ---- Parsear linea de firma ----
                # Formato: Sig: r=0x..., s=0x...
                m_sig = re.match(
                    r"^Sig:\s*r=(0x[0-9a-f]+),\s*s=(0x[0-9a-f]+)$",
                    txt, re.I
                )
                if m_sig and last_user and last_msg:
                    r_hex, s_hex = m_sig.groups()

                    # ==============================
                    # ROOM 1: Resolver con Alpha_01
                    # ==============================
                    if room == 1 and last_user == "Alpha_01" and d1 is None:
                        d1 = solve_room1(last_msg, s_hex)
                        print(f"[+] Room 1: d1 = 0x...{hex(d1)[-8:]}", flush=True)
                        sock.sendall((hex(d1) + "\n").encode())
                        room = 1.5  # Esperando validacion

                    # ==============================
                    # ROOM 2: Recolectar firmas de Exarch_01
                    # ==============================
                    if room == 2 and last_user == "Exarch_01" and len(exarch) < 2:
                        # Solo guardar si tiene r diferente (2 firmas distintas)
                        if not any(e['r'] == r_hex for e in exarch):
                            exarch.append({
                                "msg": last_msg,
                                "r": r_hex,
                                "s": s_hex
                            })
                            print(f"  [Exarch] Firma #{len(exarch)}/2", flush=True)

                    # ==============================
                    # ROOM 3: Recolectar firmas de Cracked_Core
                    # ==============================
                    if room >= 3 and last_user == "Cracked_Core":
                        rs_key = (r_hex, s_hex)
                        if rs_key not in r3_seen:
                            r3_seen.add(rs_key)
                            r3_sigs.append({
                                "msg": last_msg,
                                "r": r_hex,
                                "s": s_hex
                            })
                            print(f"  [Cracked_Core] Firma #{len(r3_sigs)}/5: "
                                  f"{last_msg[:45]}", flush=True)

                # ============================================
                # ROOM 2: Resolver cuando tengamos datos suficientes
                # ============================================
                if (room == 2 and len(exarch) >= 2
                        and len(relay_pairs) >= 8 and d2 is None):
                    print("[*] Room 2: Datos completos, resolviendo...", flush=True)

                    # Concatenar chunks de Rachel
                    A = concat_chunks(relay_pairs, "a")
                    B = concat_chunks(relay_pairs, "b")

                    # Resolver LCG
                    d2 = solve_room2(exarch[0], exarch[1], A, B)

                    if d2:
                        print(f"[+] Room 2: d2 = 0x...{hex(d2)[-8:]}", flush=True)
                        sock.sendall((hex(d2) + "\n").encode())
                    else:
                        print("[-] Room 2: Solucion directa fallo", flush=True)

                # ============================================
                # ROOM 3: Ataque Polynonce cuando tengamos 5 firmas
                # ============================================
                if room >= 3 and len(r3_sigs) >= 5 and not r3_submitted:
                    print(f"\n{'='*60}", flush=True)
                    print(f"[*] Room 3: Iniciando ataque Polynonce "
                          f"con {len(r3_sigs)} firmas", flush=True)
                    print(f"{'='*60}", flush=True)

                    # --- Paso 1: Probar LCG (grado 1) con todas las permutaciones ---
                    print("\n[*] Probando recurrencia LCG (grado 1, 120 permutaciones)...",
                          flush=True)

                    found = False
                    tested = 0
                    for perm in itertools.permutations(range(len(r3_sigs)), 4):
                        ordered = [r3_sigs[i] for i in perm]
                        try:
                            roots = attack_degree1(ordered)
                        except Exception:
                            continue
                        tested += 1

                        for d_try in roots:
                            d_try = int(d_try) % N
                            if d_try == 0:
                                continue
                            # Verificar contra firma NO usada en la ecuacion
                            remaining = [i for i in range(len(r3_sigs))
                                         if i not in perm]
                            if remaining and verify_key(d_try, r3_sigs[remaining[0]]):
                                print(f"\n  *** ENCONTRADO! LCG, orden={perm}",
                                      flush=True)
                                print(f"  d3 = {hex(d_try)}", flush=True)
                                sock.sendall((hex(d_try) + "\n").encode())
                                r3_submitted = True
                                found = True
                                break
                        if found:
                            break

                    if not found:
                        print(f"  LCG: Sin resultados ({tested} ordenes probados)",
                              flush=True)

                    # --- Paso 2: Probar recurrencia cuadratica (grado 2) ---
                    if not found:
                        print("\n[*] Probando recurrencia cuadratica (grado 2, "
                              "120 permutaciones)...", flush=True)

                        tested = 0
                        for perm in itertools.permutations(range(len(r3_sigs)), 5):
                            ordered = [r3_sigs[i] for i in perm]
                            try:
                                roots = attack_degree2(ordered)
                            except Exception:
                                continue
                            tested += 1

                            for d_try in roots:
                                d_try = int(d_try) % N
                                if d_try == 0:
                                    continue
                                # Verificar: no hay firma restante (se usan las 5)
                                # Verificamos contra la primera firma del perm
                                if verify_key(d_try, r3_sigs[perm[0]]):
                                    print(f"\n  *** ENCONTRADO! Recurrencia cuadratica, "
                                          f"orden={perm}", flush=True)
                                    print(f"  d3 = {hex(d_try)}", flush=True)
                                    sock.sendall((hex(d_try) + "\n").encode())
                                    r3_submitted = True
                                    found = True
                                    break
                            if found:
                                break

                        if not found:
                            print(f"  Cuadratica: Sin resultados "
                                  f"({tested} ordenes probados)", flush=True)

                    # Esperar resultado
                    if r3_submitted:
                        print("\n[*] Clave enviada, esperando respuesta...",
                              flush=True)
                        time.sleep(5)
                        try:
                            response = sock.recv(65536).decode(errors='replace')
                            print(response, flush=True)
                        except Exception:
                            pass
                    else:
                        print("\n[-] No se encontro recurrencia polinomial",
                              flush=True)

    except KeyboardInterrupt:
        print("\n[!] Interrumpido por usuario", flush=True)
    finally:
        sock.close()

    print(f"\n[*] Fin. Sala alcanzada: {room}", flush=True)


if __name__ == "__main__":
    main()
