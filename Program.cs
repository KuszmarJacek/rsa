using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using static Org.BouncyCastle.Crypto.Engines.SM2Engine;

namespace rsa
{
    internal class Program
    {
        private static readonly int bitLength = 2048;
        private static readonly int primerCertainty = 100;
        private static readonly SecureRandom secureRandom = new SecureRandom();

        public static BigInteger CubeRoot(BigInteger x)
        {
            BigInteger y = new BigInteger("1");
            BigInteger z = BigInteger.Zero;
            while (!y.Equals(z))
            {
                z = y;
                y = y.Multiply(new BigInteger("2")).Add(x.Divide(y.Pow(2))).Divide(new BigInteger("3"));
            }
            return y;
        }
        public static BigInteger Encrypt(string message, BigInteger e, BigInteger N)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            BigInteger messageInt = new BigInteger(messageBytes);
            BigInteger encryped = messageInt.ModPow(e, N);

            return encryped;
        }
        public static string Decrypt(BigInteger encryptedMessage, BigInteger d, BigInteger N)
        {
            BigInteger decryptedInt = encryptedMessage.ModPow(d, N);
            byte[] decryptedBytes = decryptedInt.ToByteArray();
            string decrypted = Encoding.UTF8.GetString(decryptedBytes);
            
            return decrypted;
        }
        static void Main(string[] args)
        {
            Stopwatch stopwatch = new Stopwatch();

            BigInteger p = new BigInteger(bitLength, primerCertainty, secureRandom);
            BigInteger q = new BigInteger(bitLength, primerCertainty, secureRandom);
            
            BigInteger N = p.Multiply(q);
            BigInteger phi = p.Subtract(BigInteger.ValueOf(1)).Multiply(q.Subtract(BigInteger.ValueOf(1)));
            BigInteger e = BigInteger.ValueOf(65537);
            BigInteger d = e.ModInverse(phi);
            Tuple<BigInteger, BigInteger> publicKey = (e, N).ToTuple();
            Tuple<BigInteger, BigInteger> privateKey = (d, N).ToTuple();

            //Console.WriteLine(p);
            //Console.WriteLine(q);
            //Console.WriteLine(N);
            //Console.WriteLine();
            //Console.WriteLine(phi);
            //Console.WriteLine(e);
            //Console.WriteLine(d);

            //stopwatch.Start();
            //string msg = "asdfasdasfasfasfasfqweqwffg";
            //BigInteger encrypted = Encrypt(msg, e, N);

            //Console.WriteLine(encrypted);
            //Console.WriteLine(Decrypt(encrypted, d, N));
            //stopwatch.Stop();
            //Console.WriteLine("Elapsed Time is {0} ms", stopwatch.ElapsedMilliseconds);

            // Podpis 4.1

            stopwatch.Start();
            Sha256Digest sha512digest = new Sha256Digest();
            string msgForSigning = "message :D";
            byte[] msgBytes = Encoding.UTF8.GetBytes(msgForSigning);

            sha512digest.BlockUpdate(msgBytes, 0, msgBytes.Length);
            byte[] hash = new byte[sha512digest.GetDigestSize()];
            Console.WriteLine(sha512digest.GetDigestSize());
            sha512digest.DoFinal(hash, 0);
            BigInteger hashInt = new BigInteger(hash);
            BigInteger signature = hashInt.ModPow(d, N);
            Console.WriteLine(signature.ToString(16));
            BigInteger hashFromSignature = signature.ModPow(e, N);
            Console.WriteLine();
            Console.WriteLine(hashInt.ToString(16));
            Console.WriteLine();
            Console.WriteLine(hashFromSignature.ToString(16));
            stopwatch.Stop();
            Console.WriteLine("Elapsed Time is {0} ms", stopwatch.ElapsedMilliseconds);

            // Eksperyment 1
            //string msg = "asdfasdasfasfasfasfqweqwffg";
            //byte[] msgBytes = Encoding.UTF8.GetBytes(msg);
            //BigInteger msgInt = new BigInteger(msgBytes);
            //BigInteger somePrime = new BigInteger(bitLength, primerCertainty, secureRandom);
            //BigInteger s = msgInt.ModPow(somePrime, N);
            //BigInteger m = s.ModPow(e, N);
            //Console.WriteLine(s.ToString(16));
            //Console.WriteLine(m.ToString());

            // Eksperyment 2
            //BigInteger m1 = new BigInteger(bitLength, primerCertainty, secureRandom);
            //BigInteger m2 = new BigInteger(bitLength, primerCertainty, secureRandom);
            //BigInteger m = m1.Multiply(m2).Mod(N);
            //BigInteger somePrime = new BigInteger(bitLength, primerCertainty, secureRandom);
            //BigInteger s1 = m1.ModPow(somePrime, N);
            //BigInteger s2 = m2.ModPow(somePrime, N);
            //BigInteger s1s2_signature = s1.Multiply(s2).Mod(N);
            //BigInteger m_signature = m.ModPow(somePrime, N);
            //Console.WriteLine(s1s2_signature);
            //Console.WriteLine();
            //Console.WriteLine(m_signature);
            // Oba podpisy sa takie same, dlatego nie podpisuje sie samej wiadomosci


            // Eksperyment 3
            //BigInteger messageInt = new BigInteger("2829246759667430901779973875");
            //BigInteger root = CubeRoot(messageInt);
            //Console.WriteLine(Encoding.UTF8.GetString(root.ToByteArray()));
            //return;
        }
    }
}

// Wiadomość o  jakiej maksymalnie  długości  można  podpisać  za  pomocą  tego algorytmu?
// Dlugosc wiadomosci = ilosc_bitow(N) / 8, w rzeczywistosci stosowany jest jeszcze padding

// Sprawdź czas wykonania operacji podpisywania i weryfikacji podpisu dla różnych wartości modułu, tj. dla 2048, 3072, 4096, 7680bitów
// 2048 - 102 ms
// 3072 - 312 ms
// 4096 - 726 ms
// 7680 - poddalem sie

// Umieść w pliku z odpowiedziami przykładową liczbę składającą się z 4096bitów, jak duża jest to liczba?
// 74269396537356760543653740868720470694718864072371378437599884004757798840738919917212922046164018221561140059410041510684531137188518444440727056494431328230190205610112821944319066957995552788667252615380036473887585872475614481956070452651804298519989938075607754204674609149178454348131524753568531904043282315817927127124081284322467928171191075787904375888294932413867694492434604511255242448260213274140611071712703670590508518163883309427734102767554705862696264864024577940162887765420049798234475049177479252700962893654801543555250044150610290900151660976687326682893259922126403761317038656402520747356600205378424571725365941134987897591552730803227599041793873149494242709885170374424891366140061189618412548953016034466314728874158579746719757059286322419563019890945045060931209796424990209822627414711092275443769565024044520844513715739246721192562756982942181166164045962216766049795696712092657128858146075455407918778329769905391465445018007922847824724992251957540899205647615743281238330815460814017485422881818105092472700601664297528749248178459033802336345927049654122387812727114059733820393088635525247933604081546582396271565836325938687622573302664633725576688323744394177547833445223198166792036055778726537898776334400944788011585368769912823314774168989925662848907160000326903477899709138877258121227880557923296771158536023474661047102096230358143287411225991679570603225407706169608561317494379166061223393847957031303609274821709408853340278974398730946732816311388794415637598292060756984357936225680349547165193568231777783208265373290746357935167945155307445212364858769680675059740281145389356706829854546010467455835875717514101382538503685246068846242420089516711933117328349393396996452265101413452725465566842100700772659137228399390571371015187511184342449826033460343212669589699993630376647285011487683289441970768431419589572269728553154827147263207757578330911691113739782506266241559597358497587522107123610505986252070574571293229453824727103907271691254552567336630122361088453576096516859103454394554795655583515837222250695731253749797909815838622805486912239446912075374635636645976948947235750148417990356328683709570456712359355809225859937266200887862757956313798881672700349478571988041385101800378468125548863848759339690225471374289042127039974032481056372657803009654455350519802692613186687977737221087980352067212068284856781566030497965192377686725373435390749167479943849830317503884200218616704601

// Jak dodanie funkcji skrótu wpływa na czas wykonania podpisywania i weryfikacji podpisu?
// W tym wypadku wyniki byly porownywalne przy 2048 i 3072 bitach.

// Jak dodanie funkcji wpływa na bezpieczeństwo? Czy któryś z powyższych ataków może się nadal powieść?
// Eksperyment 1: No message attack: no i co z tego ze dostaniemy podpis skoro skrot sie nie zgadza.
// Eksperyment 2: Skrot wiadomosci m, m1, m2 sie roznia, wiec znowu co z tego ze ma podpis?
// Eksperyment 3: ???
// https://www.cs.purdue.edu/homes/jblocki/courses/555_Spring17/slides/Lecture33.pdf

// Jak ustala się wartość klucza publicznego?
// Wybiera sie duze e z liczb Fermata, po wygenerowaniu p i q, mnozy sie je, w efekcie postaje N, wartosc klucza publlicznego to (N, e)

// Co to znaczy, że schemat podpisu jest bezpieczny? Jaka jest przyjęta definicja?
// Bezpieczny podpis elektroniczny musi – według ustawy o podpisie elektronicznym – być:
// - Przyporządkowany wyłącznie do osoby, która składa ten podpis.
// - Wykonany za pomocą urządzeń oraz danych podlegających wyłącznej kontroli
//   osoby składającej podpis elektroniczny.
// - Powiązany z danymi, które zostały podpisane w taki sposób, że każda zmiana
//   tych danych wykonana po złożeniu podpisu będzie rozpoznawalna.

// Wyjaśnij dlaczego ataki z pkt. 2 są możliwie do przeprowadzenia.
// Eksperyment 1: Jest to mozliwe, bo jesli mamy wiadomosc m i klucz prywatny, to zawsze wyjdzie nam ten sam wynik. Jesli chcemy sie tego pozbyc, to uzyc paddingu i RSA PSS. ???
// Eksperyment 2: Bo operacje podpisu jest mnozeniem modularnym. Zeby sie go pozbyc stosuje sie padding jak w RSA PSS. ???
// Eksperyment 3: e jest za male, wiec mozna wziac pierwiastek trzeciego stopnia z wiadomosci i otrzymac jawna wiadomosc

// Jaka wartość klucza publicznego należy wybrać, czy e może być stałe?
// Wykorzystanie e = 65537 jest czeste, wiec e moze byc stale. Nalezy wybrac wartosc klucza taka, zeby e bylo liczba Fermata, ktora jest duza.
// https://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537

// Jaka musi być wielkość modułu,
// aby uzyskać bezpieczeństwo na poziomie 256 bitów (256 bit security) i co znaczy tak określony poziom bezpieczeństwa?
// 256 bit security, w przypadku klucza prywatnego ze bedzie on mial 115,792,089,237,316,195,423,570,985,008,687,907,853,269,
// 984,665,640,564,039,457,584,007,913,129,639,936 mozliwych kombinacji
// https://www.youtube.com/watch?v=S9JGmA5_unY
// 1024-bit RSA keys are equivalent in strength to 80-bit symmetric keys,
// 2048-bit RSA keys to 112-bit symmetric keys, 3072-bit RSA keys to 128-bit symmetric keys, and 15360-bit RSA keys to 256-bit symmetric keys.
// https://en.wikipedia.org/wiki/Key_size
// https://www.keylength.com/en/4/

// Co to jest za schemat RSA-PSS? Dlaczego zaleca się jego używanie zamiast schematu RSA PKCS#1.5?
// PKCS#1.5 nie jest uzywane ze wzgledu na ataki z wykorzystaniem chose ciphertext
// https://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf
// https://medium.com/@c0D3M/bleichenbacher-attack-explained-bc630f88ff25
// PSS(Probabilistic Signature Scheme) wykorzystuje randomizowane podpisy do tej samej wiadomosci, co sprawia ze jest probabilistyczny,
// a nie deterministyczny jak PKCS#1.5

// Po co w formacie klucza prywatnego ANSI zachowuje się wartości p i q?
// p i q sa potrzebne do obliczenia d, ktoro jest potrzebne do utworzenia klucza prywatnego. Jesli atakujacy zna p i q, to moze tez poznac wartosc
// klucz prywatnego (N, d), bo N = p * q

// Jakie są inne ataki na schemat RSA oprócz tych opisanych w pkt. 2?
// Coppersmith's Theorem
// Franklin-Reiter Related Message Attack
// Copp ersmith's Short Pad Attack

// Dlaczego moduł N nie może być używany więcej niż raz?
// Jesli atakujacy zbierze kilka wiadomosci, a te wiadomosci wykorzystuja ten sam N,
// to moze on dokonac ataku na wspolny modul. Wystarcza dwie wiadomosci i rozszerzony algorytm euklidesa
// https://infosecwriteups.com/rsa-attacks-common-modulus-7bdb34f331a5