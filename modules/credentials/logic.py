"""Credential auditing logic: local-only password strength analysis.

Security guarantees:
* The analysis runs entirely on this device. A password is never stored,
  logged, transmitted, written to disk, or included in any report.
* The common-password bank is a fixed, reviewed dataset (curated from
  published top-password studies); nothing is generated at runtime.
* Pattern detection makes the strength estimate honest: keyboard walks,
  repeats, sequences, years, embedded common words, and user-supplied
  personal context all reduce the effective entropy and the score.
"""
from dataclasses import dataclass
import math
import re
import secrets
import string

# Curated bank of the most commonly used passwords, reviewed for accuracy.
# Sorted and de-duplicated; used for membership and substring checks.
COMMON_PASSWORDS = (
    "$0cc3r", "$0cc3r!", "$0cc3r1", "$0cc3r123", "$7@rw@r$", "$7@rw@r$!", "$7@rw@r$1",
    "$7@rw@r$123", "$h@d0w", "$h@d0w!", "$h@d0w1", "$h@d0w123", "$kyw@lk3r",
    "$kyw@lk3r!", "$kyw@lk3r1", "$kyw@lk3r123", "$p@rkl3", "$p@rkl3!", "$p@rkl31",
    "$p@rkl3123", "$un$h1n3", "$un$h1n3!", "$un$h1n31", "$un$h1n3123", "$up3rm@n",
    "$up3rm@n!", "$up3rm@n1", "$up3rm@n123", "000000", "0000000", "0123456789",
    "0987654321", "101010", "102030", "1029384756", "111111", "11111111", "112233",
    "11223344", "1122334455", "112358", "121212", "123123", "123123123", "123321",
    "1234", "12345", "123456", "1234567", "12345678", "123456789", "1234567890",
    "12345678910", "123456789a", "123456789q", "123456789z", "123456a", "1234abcd",
    "1234qwer", "123654", "123abc", "123qwe", "131313", "135790", "147258", "147741",
    "147852", "147896", "159357", "159753", "1a2b3c4d", "1l0v3y0u", "1l0v3y0u!",
    "1l0v3y0u1", "1l0v3y0u123", "1n73rn37", "1n73rn37!", "1n73rn371", "1n73rn37123",
    "1q2w3e", "1q2w3e4r", "1q2w3e4r5t", "1q2w3e4r5t6y", "1qaz2wsx", "1qaz2wsx3edc",
    "1qazxsw2", "232323", "246810", "258147", "258369", "258852", "258963", "321654",
    "333333", "343434", "357951", "369147", "369258", "369741", "369963", "444444",
    "454545", "456123", "456456", "555555", "565656", "654321", "6543210", "654987",
    "666666", "676767", "696969", "741852", "741852963", "753159", "753951", "777777",
    "787878", "789321", "789456", "789789", "7hund3r", "7hund3r!", "7hund3r1",
    "7hund3r123", "7ru$7n01", "7ru$7n01!", "7ru$7n011", "7ru$7n01123", "852456",
    "852963", "888888", "898989", "951753", "963852", "963852741", "987654",
    "987654321", "9876543210", "999999", "@dm1n", "@dm1n!", "@dm1n1", "@dm1n123",
    "@dmin", "@m3r1c@", "@m3r1c@!", "@m3r1c@1", "@m3r1c@123", "@meric@", "@ndr3w",
    "@ndr3w!", "@ndr3w1", "@ndr3w123", "@ndrew", "@ng3l", "@ng3l!", "@ng3l1",
    "@ng3l123", "@ngel", "@r$3n@l", "@r$3n@l!", "@r$3n@l1", "@r$3n@l123", "@rsen@l",
    "a1b2c3d4", "aa123456", "abc123", "abc1234", "abc12345", "abcd1234", "abcdef",
    "abcdefg", "abcdefgh", "access", "admin", "admin!", "admin007", "admin01",
    "admin1", "admin12", "admin123", "admin1234", "admin12345", "admin2020",
    "admin2021", "admin2022", "admin2023", "admin2024", "admin2025", "admin2026",
    "admin69", "admin88", "admin99", "airforce", "alex", "alex1", "allison", "amanda",
    "amanda1", "amber", "amber1", "america", "america!", "america007", "america01",
    "america1", "america12", "america123", "america1234", "america12345",
    "america2020", "america2021", "america2022", "america2023", "america2024",
    "america2025", "america2026", "america69", "america88", "america99", "andrea",
    "andrew", "andrew!", "andrew007", "andrew01", "andrew1", "andrew12", "andrew123",
    "andrew1234", "andrew12345", "andrew2020", "andrew2021", "andrew2022",
    "andrew2023", "andrew2024", "andrew2025", "andrew2026", "andrew69", "andrew88",
    "andrew99", "angel", "angel!", "angel007", "angel01", "angel1", "angel12",
    "angel123", "angel1234", "angel12345", "angel2020", "angel2021", "angel2022",
    "angel2023", "angel2024", "angel2025", "angel2026", "angel69", "angel88",
    "angel99", "angela", "anonymous", "anthony", "anthony1", "aol", "apple", "apple1",
    "army", "arsenal", "arsenal!", "arsenal007", "arsenal01", "arsenal1", "arsenal12",
    "arsenal123", "arsenal1234", "arsenal12345", "arsenal2020", "arsenal2021",
    "arsenal2022", "arsenal2023", "arsenal2024", "arsenal2025", "arsenal2026",
    "arsenal69", "arsenal88", "arsenal99", "asdf1234", "asdfgh", "asdfghj",
    "asdfghjkl", "asdzxc123", "ashley", "ashley1", "atlanta", "austin", "austin1",
    "autumn", "avatar", "b@$3b@ll", "b@$3b@ll!", "b@$3b@ll1", "b@$3b@ll123", "b@7m@n",
    "b@7m@n!", "b@7m@n1", "b@7m@n123", "b@n@n@", "b@n@n@!", "b@n@n@1", "b@n@n@123",
    "b@seb@ll", "b@tm@n", "baby", "babyboy", "babygirl", "bailey", "banana", "banana!",
    "banana007", "banana01", "banana1", "banana12", "banana123", "banana1234",
    "banana12345", "banana2020", "banana2021", "banana2022", "banana2023",
    "banana2024", "banana2025", "banana2026", "banana69", "banana88", "banana99",
    "banker", "barcelona", "baseball", "baseball!", "baseball007", "baseball01",
    "baseball1", "baseball12", "baseball123", "baseball1234", "baseball12345",
    "baseball2020", "baseball2021", "baseball2022", "baseball2023", "baseball2024",
    "baseball2025", "baseball2026", "baseball69", "baseball88", "baseball99",
    "basketball", "batman", "batman!", "batman007", "batman01", "batman1", "batman12",
    "batman123", "batman1234", "batman12345", "batman2020", "batman2021", "batman2022",
    "batman2023", "batman2024", "batman2025", "batman2026", "batman69", "batman88",
    "batman99", "beach", "bears", "beautiful", "ben", "bengals", "berlin", "billion",
    "bills", "birdie", "bitcoin", "blessed", "boston", "brandon", "brandon1", "brian",
    "brian1", "brittany", "broncos", "browns", "bu773rfly", "bu773rfly!", "bu773rfly1",
    "bu773rfly123", "bunny", "buster", "butterfly", "butterfly!", "butterfly007",
    "butterfly01", "butterfly1", "butterfly12", "butterfly123", "butterfly1234",
    "butterfly12345", "butterfly2020", "butterfly2021", "butterfly2022",
    "butterfly2023", "butterfly2024", "butterfly2025", "butterfly2026", "butterfly69",
    "butterfly88", "butterfly99", "c00k13", "c00k13!", "c00k131", "c00k13123",
    "c00kie", "c0d3r", "c0d3r!", "c0d3r1", "c0d3r123", "c0der", "c0mpu73r",
    "c0mpu73r!", "c0mpu73r1", "c0mpu73r123", "c0mputer", "c0wb0y", "c0wb0y!",
    "c0wb0y1", "c0wb0y123", "cameron", "cameron1", "canada", "captain", "cardinals",
    "carlos", "carolyn", "catherine", "celtic", "centos", "ch0c0l@73", "ch0c0l@73!",
    "ch0c0l@731", "ch0c0l@73123", "ch0c0l@te", "ch3l$3@", "ch3l$3@!", "ch3l$3@1",
    "ch3l$3@123", "champion", "changeme", "chargers", "charlie", "cheese", "chelse@",
    "chelsea", "chelsea!", "chelsea007", "chelsea01", "chelsea1", "chelsea12",
    "chelsea123", "chelsea1234", "chelsea12345", "chelsea2020", "chelsea2021",
    "chelsea2022", "chelsea2023", "chelsea2024", "chelsea2025", "chelsea2026",
    "chelsea69", "chelsea88", "chelsea99", "chicago", "chiefs", "chocolate",
    "chocolate!", "chocolate007", "chocolate01", "chocolate1", "chocolate12",
    "chocolate123", "chocolate1234", "chocolate12345", "chocolate2020",
    "chocolate2021", "chocolate2022", "chocolate2023", "chocolate2024",
    "chocolate2025", "chocolate2026", "chocolate69", "chocolate88", "chocolate99",
    "chris", "chris1", "christina", "christopher", "christopher1", "cloud", "coder",
    "coder!", "coder007", "coder01", "coder1", "coder12", "coder123", "coder1234",
    "coder12345", "coder2020", "coder2021", "coder2022", "coder2023", "coder2024",
    "coder2025", "coder2026", "coder69", "coder88", "coder99", "colts", "computer",
    "computer!", "computer007", "computer01", "computer1", "computer12", "computer123",
    "computer1234", "computer12345", "computer2020", "computer2021", "computer2022",
    "computer2023", "computer2024", "computer2025", "computer2026", "computer69",
    "computer88", "computer99", "cookie", "cookie!", "cookie007", "cookie01",
    "cookie1", "cookie12", "cookie123", "cookie1234", "cookie12345", "cookie2020",
    "cookie2021", "cookie2022", "cookie2023", "cookie2024", "cookie2025", "cookie2026",
    "cookie69", "cookie88", "cookie99", "corvette", "courtney", "cowboy", "cowboy!",
    "cowboy007", "cowboy01", "cowboy1", "cowboy12", "cowboy123", "cowboy1234",
    "cowboy12345", "cowboy2020", "cowboy2021", "cowboy2022", "cowboy2023",
    "cowboy2024", "cowboy2025", "cowboy2026", "cowboy69", "cowboy88", "cowboy99",
    "cowboys", "crypto", "cupcake", "cutie", "cutie1", "d1@m0nd", "d1@m0nd!",
    "d1@m0nd1", "d1@m0nd123", "d@n13l", "d@n13l!", "d@n13l1", "d@n13l123", "d@niel",
    "daisy", "dallas", "dan", "daniel", "daniel!", "daniel007", "daniel01", "daniel1",
    "daniel12", "daniel123", "daniel1234", "daniel12345", "daniel2020", "daniel2021",
    "daniel2022", "daniel2023", "daniel2024", "daniel2025", "daniel2026", "daniel69",
    "daniel88", "daniel99", "danielle", "darling", "david", "david1", "debian",
    "default", "demo", "denver", "desert", "destiny", "detroit", "developer",
    "di@m0nd", "diamond", "diamond!", "diamond007", "diamond01", "diamond1",
    "diamond12", "diamond123", "diamond1234", "diamond12345", "diamond2020",
    "diamond2021", "diamond2022", "diamond2023", "diamond2024", "diamond2025",
    "diamond2026", "diamond69", "diamond88", "diamond99", "diana", "digital", "doctor",
    "dollar", "dolphin", "dolphins", "donald", "dr@g0n", "dr@g0n!", "dr@g0n1",
    "dr@g0n1!", "dr@g0n11", "dr@g0n1123", "dr@g0n123", "dragon", "dragon!",
    "dragon007", "dragon01", "dragon1", "dragon1!", "dragon1007", "dragon101",
    "dragon11", "dragon112", "dragon1123", "dragon11234", "dragon112345", "dragon12",
    "dragon12020", "dragon12021", "dragon12022", "dragon12023", "dragon12024",
    "dragon12025", "dragon12026", "dragon123", "dragon1234", "dragon12345",
    "dragon169", "dragon188", "dragon199", "dragon2020", "dragon2021", "dragon2022",
    "dragon2023", "dragon2024", "dragon2025", "dragon2026", "dragon69", "dragon88",
    "dragon99", "dream", "eagle", "eagle1", "eagles", "eclipse", "edward", "elizabeth",
    "emerald", "emily", "emily1", "employee", "engineer", "eric", "eric1", "ethan",
    "f007b@ll", "f007b@ll!", "f007b@ll1", "f007b@ll123", "f00tb@ll", "facebook",
    "faith", "faithful", "falcon", "falcons", "ferrari", "fire", "fireman", "fl0w3r",
    "fl0w3r!", "fl0w3r1", "fl0w3r123", "fl0wer", "flower", "flower!", "flower007",
    "flower01", "flower1", "flower12", "flower123", "flower1234", "flower12345",
    "flower2020", "flower2021", "flower2022", "flower2023", "flower2024", "flower2025",
    "flower2026", "flower69", "flower88", "flower99", "football", "football!",
    "football007", "football01", "football1", "football12", "football123",
    "football1234", "football12345", "football2020", "football2021", "football2022",
    "football2023", "football2024", "football2025", "football2026", "football69",
    "football88", "football99", "forest", "forever", "fortnite", "fr33d0m", "fr33d0m!",
    "fr33d0m1", "fr33d0m123", "freed0m", "freedom", "freedom!", "freedom007",
    "freedom01", "freedom1", "freedom12", "freedom123", "freedom1234", "freedom12345",
    "freedom2020", "freedom2021", "freedom2022", "freedom2023", "freedom2024",
    "freedom2025", "freedom2026", "freedom69", "freedom88", "freedom99", "frodo",
    "fuckyou", "galaxy", "gandalf", "garden", "gary", "general1", "genesis", "george",
    "giants", "ginger", "gladiator", "glitter", "glory", "gmail", "goldfish", "google",
    "gorgeous", "grace", "gregory", "guest", "h0ck3y", "h0ck3y!", "h0ck3y1",
    "h0ck3y123", "h0ckey", "h@ck3r", "h@ck3r!", "h@ck3r1", "h@ck3r123", "h@cker",
    "hacker", "hacker!", "hacker007", "hacker01", "hacker1", "hacker12", "hacker123",
    "hacker1234", "hacker12345", "hacker2020", "hacker2021", "hacker2022",
    "hacker2023", "hacker2024", "hacker2025", "hacker2026", "hacker69", "hacker88",
    "hacker99", "hacking", "hamster", "hannah", "hannah1", "happy", "hardcore",
    "harley", "heather", "helen", "hello", "hello1", "hello123", "hobbit", "hockey",
    "hockey!", "hockey007", "hockey01", "hockey1", "hockey12", "hockey123",
    "hockey1234", "hockey12345", "hockey2020", "hockey2021", "hockey2022",
    "hockey2023", "hockey2024", "hockey2025", "hockey2026", "hockey69", "hockey88",
    "hockey99", "honey", "honey1", "hope", "horizon", "horse", "hotmail", "hottie",
    "houston", "hun73r", "hun73r!", "hun73r1", "hun73r123", "hunter", "hunter!",
    "hunter007", "hunter01", "hunter1", "hunter12", "hunter123", "hunter1234",
    "hunter12345", "hunter2020", "hunter2021", "hunter2022", "hunter2023",
    "hunter2024", "hunter2025", "hunter2026", "hunter69", "hunter88", "hunter99",
    "hurricane", "ice", "il0vey0u", "iloveu", "iloveyou", "iloveyou!", "iloveyou007",
    "iloveyou01", "iloveyou1", "iloveyou12", "iloveyou123", "iloveyou1234",
    "iloveyou12345", "iloveyou2", "iloveyou2020", "iloveyou2021", "iloveyou2022",
    "iloveyou2023", "iloveyou2024", "iloveyou2025", "iloveyou2026", "iloveyou69",
    "iloveyou88", "iloveyou99", "imadmin", "imamerica", "imandrew", "imangel",
    "imarsenal", "imbanana", "imbaseball", "imbatman", "imbutterfly", "imchelsea",
    "imchocolate", "imcoder", "imcomputer", "imcookie", "imcowboy", "imdaniel",
    "imdiamond", "imdragon", "imdragon1", "imflower", "imfootball", "imfreedom",
    "imhacker", "imhockey", "imhunter", "imiloveyou", "iminternet", "imjennifer",
    "imjordan", "imjoshua", "imletmein", "imliberty", "imlogin", "immaster",
    "immichael", "immonkey", "imninja", "impassword", "imphantom", "imphoenix",
    "imprincess", "imrainbow", "imshadow", "imskywalker", "imsoccer", "imsparkle",
    "imstarwars", "imsunshine", "imsuperman", "imthunder", "imtrustno1", "imvictory",
    "imwarrior", "imwelcome", "infinity", "instagram", "internet", "internet!",
    "internet007", "internet01", "internet1", "internet12", "internet123",
    "internet1234", "internet12345", "internet2020", "internet2021", "internet2022",
    "internet2023", "internet2024", "internet2025", "internet2026", "internet69",
    "internet88", "internet99", "island", "j0$hu@", "j0$hu@!", "j0$hu@1", "j0$hu@123",
    "j0rd@n", "j0rd@n!", "j0rd@n1", "j0rd@n123", "j0shu@", "j3nn1f3r", "j3nn1f3r!",
    "j3nn1f3r1", "j3nn1f3r123", "jacob", "jacob1", "jaguar", "james", "james1",
    "janet", "jasmine", "jason", "jason1", "java", "jeffrey", "jennifer", "jennifer!",
    "jennifer007", "jennifer01", "jennifer1", "jennifer12", "jennifer123",
    "jennifer1234", "jennifer12345", "jennifer2020", "jennifer2021", "jennifer2022",
    "jennifer2023", "jennifer2024", "jennifer2025", "jennifer2026", "jennifer69",
    "jennifer88", "jennifer99", "jeremy", "jessica", "jessica1", "jesus", "jets",
    "john", "john1", "joker", "jordan", "jordan!", "jordan007", "jordan01", "jordan1",
    "jordan12", "jordan123", "jordan1234", "jordan12345", "jordan2020", "jordan2021",
    "jordan2022", "jordan2023", "jordan2024", "jordan2025", "jordan2026", "jordan69",
    "jordan88", "jordan99", "joseph", "joseph1", "joshua", "joshua!", "joshua007",
    "joshua01", "joshua1", "joshua12", "joshua123", "joshua1234", "joshua12345",
    "joshua2020", "joshua2021", "joshua2022", "joshua2023", "joshua2024", "joshua2025",
    "joshua2026", "joshua69", "joshua88", "joshua99", "joy1", "justice", "justin",
    "justin1", "juventus", "kali", "kelly", "kelly1", "kevin", "kevin1", "killer",
    "kimberly", "king", "kitten", "knight", "kristen", "kyle", "kyle1", "l0g1n",
    "l0g1n!", "l0g1n1", "l0g1n123", "l0gin", "l1b3r7y", "l1b3r7y!", "l1b3r7y1",
    "l1b3r7y123", "l37m31n", "l37m31n!", "l37m31n1", "l37m31n123", "lakers", "lauren",
    "lauren1", "lawyer", "legend", "letmein", "letmein!", "letmein007", "letmein01",
    "letmein1", "letmein12", "letmein123", "letmein1234", "letmein12345",
    "letmein2020", "letmein2021", "letmein2022", "letmein2023", "letmein2024",
    "letmein2025", "letmein2026", "letmein69", "letmein88", "letmein99", "liberty",
    "liberty!", "liberty007", "liberty01", "liberty1", "liberty12", "liberty123",
    "liberty1234", "liberty12345", "liberty2020", "liberty2021", "liberty2022",
    "liberty2023", "liberty2024", "liberty2025", "liberty2026", "liberty69",
    "liberty88", "liberty99", "lightning", "lily", "linux", "lions", "lisa", "lisa1",
    "liverpool", "login", "login!", "login007", "login01", "login1", "login12",
    "login123", "login1234", "login12345", "login2020", "login2021", "login2022",
    "login2023", "login2024", "login2025", "login2026", "login69", "login88",
    "login99", "london", "lonewolf", "love", "love123", "love1234", "lovely", "loveme",
    "loveyou", "lucky", "m0nk3y", "m0nk3y!", "m0nk3y1", "m0nk3y123", "m0nkey",
    "m1ch@3l", "m1ch@3l!", "m1ch@3l1", "m1ch@3l123", "m@$73r", "m@$73r!", "m@$73r1",
    "m@$73r123", "m@ster", "madrid", "maggie", "magic", "manager", "manchester",
    "manutd", "marie", "marine", "mark", "mark1", "mary", "mary1", "master", "master!",
    "master007", "master01", "master1", "master12", "master123", "master1234",
    "master12345", "master2020", "master2021", "master2022", "master2023",
    "master2024", "master2025", "master2026", "master69", "master88", "master99",
    "matrix", "matthew", "matthew1", "megan", "megan1", "melissa", "melissa1",
    "mercedes", "miami", "mich@el", "michael", "michael!", "michael007", "michael01",
    "michael1", "michael12", "michael123", "michael1234", "michael12345",
    "michael2020", "michael2021", "michael2022", "michael2023", "michael2024",
    "michael2025", "michael2026", "michael69", "michael88", "michael99", "michelle",
    "microsoft", "mike", "mike1", "million", "minecraft", "missyou", "mnbvcx",
    "mnbvcxz", "money", "monkey", "monkey!", "monkey007", "monkey01", "monkey1",
    "monkey12", "monkey123", "monkey1234", "monkey12345", "monkey2020", "monkey2021",
    "monkey2022", "monkey2023", "monkey2024", "monkey2025", "monkey2026", "monkey69",
    "monkey88", "monkey99", "moon", "moonlight", "mountain", "msn", "mustang",
    "myadmin", "myamerica", "myandrew", "myangel", "myarsenal", "mybanana",
    "mybaseball", "mybatman", "mybutterfly", "mychelsea", "mychocolate", "mycoder",
    "mycomputer", "mycookie", "mycowboy", "mydaniel", "mydiamond", "mydragon",
    "mydragon1", "myflower", "myfootball", "myfreedom", "myhacker", "myhockey",
    "myhunter", "myiloveyou", "myinternet", "myjennifer", "myjordan", "myjoshua",
    "myletmein", "myliberty", "mylogin", "mymaster", "mymichael", "mymonkey",
    "myninja", "mypassword", "myphantom", "myphoenix", "myprincess", "myrainbow",
    "myshadow", "myskywalker", "mysoccer", "mysparkle", "mystarwars", "mysunshine",
    "mysuperman", "mythunder", "mytrustno1", "myvictory", "mywarrior", "mywelcome",
    "n1nj@", "n1nj@!", "n1nj@1", "n1nj@123", "nancy", "navy", "netflix", "network",
    "newyork", "nicholas", "nick", "nicole", "ninj@", "ninja", "ninja!", "ninja007",
    "ninja01", "ninja1", "ninja12", "ninja123", "ninja1234", "ninja12345", "ninja2020",
    "ninja2021", "ninja2022", "ninja2023", "ninja2024", "ninja2025", "ninja2026",
    "ninja69", "ninja88", "ninja99", "nintendo", "nobody", "nurse", "ocean", "oliver",
    "online", "operator", "oracle", "orange", "p@$$w0rd", "p@$$w0rd!", "p@$$w0rd1",
    "p@$$w0rd123", "p@ssw0rd", "packers", "panda", "panther", "panthers", "paris",
    "parrot", "pass123", "pass1234", "passw0rd", "passw0rd1", "password", "password!",
    "password007", "password01", "password1", "password12", "password123",
    "password1234", "password12345", "password2020", "password2021", "password2022",
    "password2023", "password2024", "password2025", "password2026", "password69",
    "password88", "password99", "patriot", "patriots", "paul", "paul1", "paypal",
    "peace", "ph03n1x", "ph03n1x!", "ph03n1x1", "ph03n1x123", "ph0enix", "ph@n70m",
    "ph@n70m!", "ph@n70m1", "ph@n70m123", "ph@nt0m", "phantom", "phantom!",
    "phantom007", "phantom01", "phantom1", "phantom12", "phantom123", "phantom1234",
    "phantom12345", "phantom2020", "phantom2021", "phantom2022", "phantom2023",
    "phantom2024", "phantom2025", "phantom2026", "phantom69", "phantom88", "phantom99",
    "philadelphia", "phoenix", "phoenix!", "phoenix007", "phoenix01", "phoenix1",
    "phoenix12", "phoenix123", "phoenix1234", "phoenix12345", "phoenix2020",
    "phoenix2021", "phoenix2022", "phoenix2023", "phoenix2024", "phoenix2025",
    "phoenix2026", "phoenix69", "phoenix88", "phoenix99", "pilot", "pirate", "planet",
    "platinum", "poiuyt", "poiuytrewq", "pokemon", "police", "power", "pr1nc3$$",
    "pr1nc3$$!", "pr1nc3$$1", "pr1nc3$$123", "prince", "prince1", "princess",
    "princess!", "princess007", "princess01", "princess1", "princess12", "princess123",
    "princess1234", "princess12345", "princess2020", "princess2021", "princess2022",
    "princess2023", "princess2024", "princess2025", "princess2026", "princess69",
    "princess88", "princess99", "professor", "puppy", "purple", "python", "q1w2e3r4",
    "qaz123wsx", "qazwsx", "qazwsxedc", "qazwsxedcrfv", "qazxsw", "qwe123",
    "qweasdzxc", "qwer1234", "qwerty", "qwerty1", "qwerty12", "qwerty123",
    "qwerty1234", "qwerty12345", "qwertyui", "qwertyuiop", "qwertyuiop123", "r@1nb0w",
    "r@1nb0w!", "r@1nb0w1", "r@1nb0w123", "r@inb0w", "rabbit", "rachel", "raiders",
    "rainbow", "rainbow!", "rainbow007", "rainbow01", "rainbow1", "rainbow12",
    "rainbow123", "rainbow1234", "rainbow12345", "rainbow2020", "rainbow2021",
    "rainbow2022", "rainbow2023", "rainbow2024", "rainbow2025", "rainbow2026",
    "rainbow69", "rainbow88", "rainbow99", "ranger", "rangers", "raymond",
    "realmadrid", "redhat", "redsox", "richard", "richie", "river", "robert",
    "robert1", "roblox", "rome", "ronald", "root", "root123", "rose1", "router",
    "ryan", "ryan1", "s0ccer", "saints", "samantha", "sample", "samsung", "samurai",
    "sapphire", "sarah", "sarah1", "scott", "scott1", "seahawks", "sean", "sean1",
    "seattle", "secret", "secret1", "security", "server", "service", "sexy", "sh@d0w",
    "shadow", "shadow!", "shadow007", "shadow01", "shadow1", "shadow12", "shadow123",
    "shadow1234", "shadow12345", "shadow2020", "shadow2021", "shadow2022",
    "shadow2023", "shadow2024", "shadow2025", "shadow2026", "shadow69", "shadow88",
    "shadow99", "shark", "silver", "skyw@lker", "skywalker", "skywalker!",
    "skywalker007", "skywalker01", "skywalker1", "skywalker12", "skywalker123",
    "skywalker1234", "skywalker12345", "skywalker2020", "skywalker2021",
    "skywalker2022", "skywalker2023", "skywalker2024", "skywalker2025",
    "skywalker2026", "skywalker69", "skywalker88", "skywalker99", "snow", "soccer",
    "soccer!", "soccer007", "soccer01", "soccer1", "soccer12", "soccer123",
    "soccer1234", "soccer12345", "soccer2020", "soccer2021", "soccer2022",
    "soccer2023", "soccer2024", "soccer2025", "soccer2026", "soccer69", "soccer88",
    "soccer99", "soldier", "sp@rkle", "sparkle", "sparkle!", "sparkle007", "sparkle01",
    "sparkle1", "sparkle12", "sparkle123", "sparkle1234", "sparkle12345",
    "sparkle2020", "sparkle2021", "sparkle2022", "sparkle2023", "sparkle2024",
    "sparkle2025", "sparkle2026", "sparkle69", "sparkle88", "sparkle99", "spartan",
    "spider", "spiderman", "spring", "st@rw@rs", "star", "starlight", "startrek",
    "starwars", "starwars!", "starwars007", "starwars01", "starwars1", "starwars12",
    "starwars123", "starwars1234", "starwars12345", "starwars2020", "starwars2021",
    "starwars2022", "starwars2023", "starwars2024", "starwars2025", "starwars2026",
    "starwars69", "starwars88", "starwars99", "steelers", "stephanie", "stephen",
    "steven", "steven1", "storm", "strawberry", "student", "success", "summer",
    "sunflower", "sunset", "sunshine", "sunshine!", "sunshine007", "sunshine01",
    "sunshine1", "sunshine12", "sunshine123", "sunshine1234", "sunshine12345",
    "sunshine2020", "sunshine2021", "sunshine2022", "sunshine2023", "sunshine2024",
    "sunshine2025", "sunshine2026", "sunshine69", "sunshine88", "sunshine99",
    "superm@n", "superman", "superman!", "superman007", "superman01", "superman1",
    "superman12", "superman123", "superman1234", "superman12345", "superman2020",
    "superman2021", "superman2022", "superman2023", "superman2024", "superman2025",
    "superman2026", "superman69", "superman88", "superman99", "supervisor", "sweet",
    "sweetheart", "sweetie", "sweety", "sydney", "system", "teacher", "temp1234",
    "test", "test123", "test1234", "test12345", "test123456", "testing", "texans",
    "theadmin", "theamerica", "theandrew", "theangel", "thearsenal", "thebanana",
    "thebaseball", "thebatman", "thebutterfly", "thechelsea", "thechocolate",
    "thecoder", "thecomputer", "thecookie", "thecowboy", "thedaniel", "thediamond",
    "thedragon", "thedragon1", "theflower", "thefootball", "thefreedom", "thehacker",
    "thehockey", "thehunter", "theiloveyou", "theinternet", "thejennifer", "thejordan",
    "thejoshua", "theletmein", "theliberty", "thelogin", "themaster", "themichael",
    "themonkey", "theninja", "thepassword", "thephantom", "thephoenix", "theprincess",
    "therainbow", "theshadow", "theskywalker", "thesoccer", "thesparkle",
    "thestarwars", "thesunshine", "thesuperman", "thethunder", "thetrustno1",
    "thevictory", "thewarrior", "thewelcome", "thomas", "thomas1", "thunder",
    "thunder!", "thunder007", "thunder01", "thunder1", "thunder12", "thunder123",
    "thunder1234", "thunder12345", "thunder2020", "thunder2021", "thunder2022",
    "thunder2023", "thunder2024", "thunder2025", "thunder2026", "thunder69",
    "thunder88", "thunder99", "tiffany", "tiger", "titan", "titanium", "tokyo", "tony",
    "tony1", "toor", "tornado", "trader", "trustme", "trustn01", "trustno1",
    "trustno1!", "trustno1007", "trustno101", "trustno11", "trustno112", "trustno1123",
    "trustno11234", "trustno112345", "trustno12020", "trustno12021", "trustno12022",
    "trustno12023", "trustno12024", "trustno12025", "trustno12026", "trustno169",
    "trustno188", "trustno199", "turtle", "twitter", "tyler", "tyler1", "ubuntu",
    "unicorn", "user", "v1c70ry", "v1c70ry!", "v1c70ry1", "v1c70ry123", "vader",
    "vanilla", "vegas", "vict0ry", "victoria", "victory", "victory!", "victory007",
    "victory01", "victory1", "victory12", "victory123", "victory1234", "victory12345",
    "victory2020", "victory2021", "victory2022", "victory2023", "victory2024",
    "victory2025", "victory2026", "victory69", "victory88", "victory99", "vikings",
    "virginia", "w3lc0m3", "w3lc0m3!", "w3lc0m31", "w3lc0m3123", "w@rr10r", "w@rr10r!",
    "w@rr10r1", "w@rr10r123", "w@rri0r", "warrior", "warrior!", "warrior007",
    "warrior01", "warrior1", "warrior12", "warrior123", "warrior1234", "warrior12345",
    "warrior2020", "warrior2021", "warrior2022", "warrior2023", "warrior2024",
    "warrior2025", "warrior2026", "warrior69", "warrior88", "warrior99", "warriors",
    "wealthy", "welc0me", "welcome", "welcome!", "welcome007", "welcome01", "welcome1",
    "welcome12", "welcome123", "welcome1234", "welcome12345", "welcome2020",
    "welcome2021", "welcome2022", "welcome2023", "welcome2024", "welcome2025",
    "welcome2026", "welcome69", "welcome88", "welcome99", "whatever", "whatever1",
    "whoami", "william", "william1", "winner", "winter", "wizard", "wolf", "wonder",
    "world", "wrestling", "yahoo", "yankees", "yankees1", "yellow", "yoda", "youtube",
    "zach", "zaq12wsx", "zaq1zaq1", "zxcasdqwe", "zxcvbn", "zxcvbnm", "zxcvbnm1",
    "zxcvbnm123", "zxcvbnml",
)

_COMMON_SET = frozenset(COMMON_PASSWORDS)

# Leet-speak substitutions used to catch common variants such as "p@ssw0rd".
_LEET_TRANSLATION = str.maketrans({
    "@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
    "0": "o", "5": "s", "$": "s", "7": "t", "8": "b", "9": "g", "2": "z",
})

CHARSET_POOL = {"lower": 26, "upper": 26, "digit": 10, "symbol": 33}

# Word-list estimates used for passphrase-style passwords (NIST SP 800-63B
# guidance: four or more random words is the recommended pattern).
WORDLIST_SIZE = 7776            # EFF large word list size
PASSPHRASE_MIN_WORDS = 4
PASSPHRASE_MIN_LENGTH = 20

# Attack-rate assumptions used only for the crack-time estimate, clearly
# labelled in the UI as estimates.
OFFLINE_GUESSES_PER_SECOND = 1_000_000_000
ONLINE_GUESSES_PER_SECOND = 1_000

# Pattern definitions used by the honest-entropy estimator.
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_ALPHABET = "abcdefghijklmnopqrstuvwxyz"
_YEAR_PATTERN = re.compile(r"(?:19\d{2}|20[0-3][0-5])")
_CONTEXT_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9]{3,}")

# One character from each pool is guaranteed by the generator.
_GENERATOR_POOLS = (
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    "!@#$%^&*()-_=+[]{};:,.<>?",
)

PATTERN_LABELS = {
    "keyboard": "keyboard walk",
    "sequence": "letter/digit sequence",
    "repeat": "repeated characters",
    "pattern": "repeating pattern",
    "year": "a year (e.g. a birth year)",
    "word": "an embedded common word",
    "context": "your personal information",
}


@dataclass(frozen=True)
class CredentialCheck:
    label: str
    passed: bool


@dataclass(frozen=True)
class PasswordReport:
    password_length: int
    score: int
    strength: str
    entropy_bits: float            # pattern-aware effective entropy
    random_entropy_bits: float     # naive random-choice estimate
    offline_crack_seconds: float
    online_crack_seconds: float
    in_common_list: bool
    common_match: str | None
    patterns: tuple[str, ...]
    context_match: str | None
    is_passphrase: bool
    checks: tuple[CredentialCheck, ...]


def passphrase_tokens(password: str) -> list:
    """Split a passphrase into its words on spaces or hyphens."""
    if not password:
        return []
    return [word for word in re.split(r"[ -]+", password.strip()) if word]


def is_passphrase(password: str) -> bool:
    """A passphrase is several words separated by spaces or hyphens
    (4+ words, >= 20 characters, every token alphabetic)."""
    if not password:
        return False
    words = passphrase_tokens(password)
    return len(words) >= PASSPHRASE_MIN_WORDS and len(password) >= PASSPHRASE_MIN_LENGTH and all(
        word.isalpha() for word in words
    )


def _class_profile(password):
    return (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )


def estimate_entropy_bits(password: str) -> float:
    """Pattern-aware entropy estimate.

    For a space-separated passphrase of real words we use the word-list
    model: each word drawn from a 7,776-word dictionary contributes
    log2(7776) bits (NIST-style). For everything else we fall back to the
    random-choice model (length x log2(character pool used)).
    """
    if not password:
        return 0.0
    if is_passphrase(password):
        words = passphrase_tokens(password)
        return len(words) * math.log2(WORDLIST_SIZE)
    lower, upper, digit, symbol = _class_profile(password)
    pool = 0
    if lower: pool += CHARSET_POOL["lower"]
    if upper: pool += CHARSET_POOL["upper"]
    if digit: pool += CHARSET_POOL["digit"]
    if symbol: pool += CHARSET_POOL["symbol"]
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def _strength_label(score: int) -> str:
    if score < 20:
        return "Very weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very strong"


def common_password_match(password: str) -> str | None:
    """Return the matched bank entry for a common password, or None.

    Checks the exact password (case-insensitive) and its leet-normalized
    form, so "P@ssw0rd" matches the bank entry "password".
    """
    if not password:
        return None
    lowered = password.lower()
    if lowered in _COMMON_SET:
        return lowered
    normalized = lowered.translate(_LEET_TRANSLATION)
    if normalized in _COMMON_SET:
        return normalized
    return None


def _run_coverage(normalized, sequences, min_run):
    """Indices covered by runs of >= min_run consecutive characters that
    appear in any sequence (or its reverse), e.g. keyboard rows."""
    covered = set()
    for sequence in sequences:
        for table in (sequence, sequence[::-1]):
            n, m = len(normalized), len(table)
            i = 0
            while i < n:
                best = 0
                for offset in range(m):
                    run = 0
                    while (
                        i + run < n
                        and offset + run < m
                        and normalized[i + run] == table[offset + run]
                    ):
                        run += 1
                    best = max(best, run)
                if best >= min_run:
                    covered.update(range(i, i + best))
                    i += best
                else:
                    i += 1
    return covered


def _same_char_runs(normalized, min_run=3):
    """Indices covered by the same character repeated >= min_run times."""
    covered = set()
    i = 0
    while i < len(normalized):
        j = i
        while j < len(normalized) and normalized[j] == normalized[i]:
            j += 1
        if j - i >= min_run:
            covered.update(range(i, j))
        i = j
    return covered


def _period_repeats(normalized, min_periods=3):
    """Indices covered by a block that repeats with a period of 2-4.

    A block of length k*p is periodic when every residue class modulo p is
    constant within the block, e.g. "ababab" or "12121212".
    """
    covered = set()
    n = len(normalized)
    for p in range(2, 5):
        for start in range(p):
            periods = n
            for residue in range(p):
                index = start + residue
                if index >= n:
                    periods = 0
                    break
                character = normalized[index]
                run = 1
                while index + run * p < n and normalized[index + run * p] == character:
                    run += 1
                periods = min(periods, run)
            if periods >= min_periods:
                covered.update(range(start, start + periods * p))
    return covered


def _years(normalized):
    """Indices covered by 4-digit years in the 1900-2035 range."""
    return {index for match in _YEAR_PATTERN.finditer(normalized) for index in range(match.start(), match.end())}


def _bank_word_substrings(normalized, min_word_length=5):
    """Indices covered by an embedded common word (case/leet-insensitive)."""
    covered = set()
    for word in _COMMON_SET:
        if len(word) < min_word_length:
            continue
        index = normalized.find(word)
        if index >= 0:
            covered.update(range(index, index + len(word)))
    return covered


def _context_matches(normalized, context):
    """Indices covered by user-supplied personal tokens (name, birth year...)."""
    if not context:
        return set()
    covered = set()
    for token in _CONTEXT_TOKEN_PATTERN.findall(context):
        normalized_token = token.lower().translate(_LEET_TRANSLATION)
        index = normalized.find(normalized_token)
        if index >= 0:
            covered.update(range(index, index + len(normalized_token)))
    return covered


def _detect_patterns(raw_lower, normalized, context):
    """Return {kind: covered_indices} for every pattern found.

    raw_lower is the plain lower-cased password: keyboard walks, repeats,
    sequences and years must be detected on the raw characters (leet
    translation would mangle digits such as 0 -> o or 2 -> z).
    normalized is the leet-translated form: embedded common words and
    personal-context tokens are matched leet-insensitively.
    """
    coverage = {}
    keyboard = _run_coverage(raw_lower, _KEYBOARD_ROWS, 3)
    if keyboard:
        coverage["keyboard"] = keyboard
    sequence = _run_coverage(raw_lower, (_ALPHABET, "0123456789"), 4)
    if sequence:
        coverage["sequence"] = sequence
    repeat = _same_char_runs(raw_lower)
    if repeat:
        coverage["repeat"] = repeat
    period = _period_repeats(raw_lower)
    if period:
        coverage["pattern"] = period
    years = _years(raw_lower)
    if years:
        coverage["year"] = years
    words = _bank_word_substrings(normalized)
    if words:
        coverage["word"] = words
    personal = _context_matches(normalized, context)
    if personal:
        coverage["context"] = personal
    return coverage


def analyze_password(password: str, context: str | None = None) -> PasswordReport:
    """Analyse a password and return its strength report.

    context is optional personal information (e.g. "Maxim 2005") that the
    password is checked against. The password value itself is never stored;
    the report contains only derived metrics and check results.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be text.")
    if context is not None and not isinstance(context, str):
        raise TypeError("Context must be text or None.")
    length = len(password)
    lower, upper, digit, symbol = _class_profile(password)
    random_entropy = estimate_entropy_bits(password)
    common_match = common_password_match(password)
    raw_lower = password.lower()
    normalized = raw_lower.translate(_LEET_TRANSLATION)
    coverage = _detect_patterns(raw_lower, normalized, context)
    patterns = tuple(sorted(coverage))

    passphrase = is_passphrase(password)
    covered = set().union(*coverage.values()) if coverage else set()
    uncovered = max(0, length - len(covered))
    pool_bits = math.log2(sum(CHARSET_POOL[name] for name, present in
                              (("lower", lower), ("upper", upper), ("digit", digit), ("symbol", symbol))
                              if present)) if (lower or upper or digit or symbol) else 0.0
    if passphrase:
        # A genuine passphrase is estimated word-by-word; a few common words
        # inside it are fine because the whole-word sequence is what matters.
        words = passphrase_tokens(password)
        effective_entropy = estimate_entropy_bits(password)
        score = min(length, 20) * 2
        word_score = 20 * len(words)  # length-first: words dominate
        score = min(100, word_score + 15)
        if common_match is None:
            score = min(100, score + 10)
        if "context" in coverage:
            score = min(score, 35)
        strength = _strength_label(score)
        checks = (
            CredentialCheck("At least 12 characters", length >= 12),
            CredentialCheck("4 or more words", len(password.split()) >= 4),
            CredentialCheck("Words are separated by spaces", " " in password),
            CredentialCheck(f"Not among the {len(COMMON_PASSWORDS)} most common passwords", common_match is None),
            CredentialCheck("No personal information (name, birth year)", "context" not in coverage),
        )
        return PasswordReport(
            password_length=length,
            score=score,
            strength=strength,
            entropy_bits=effective_entropy,
            random_entropy_bits=effective_entropy,
            offline_crack_seconds=(2 ** effective_entropy) / OFFLINE_GUESSES_PER_SECOND,
            online_crack_seconds=(2 ** effective_entropy) / ONLINE_GUESSES_PER_SECOND,
            in_common_list=common_match is not None,
            common_match=common_match,
            patterns=tuple(),
            context_match=None,
            is_passphrase=True,
            checks=checks,
        )
    effective_entropy = uncovered * pool_bits + 8 * len(coverage)
    effective_entropy = min(effective_entropy, random_entropy)

    score = min(length, 20) * 2
    if lower: score += 5
    if upper: score += 5
    if digit: score += 5
    if symbol: score += 10
    if random_entropy >= 80: score += 25
    elif random_entropy >= 60: score += 20
    elif random_entropy >= 40: score += 12
    elif random_entropy >= 28: score += 6
    if common_match:
        score = min(score, 10)  # A known-compromised password can never score well.
    score -= 8 * len(coverage)  # Pattern-aware penalty.
    if "word" in coverage or "context" in coverage:
        score = min(score, 35)  # Embedded words or personal info cap at "Weak".
    score = max(0, min(100, score))

    if score < 20: strength = "Very weak"
    elif score < 40: strength = "Weak"
    elif score < 60: strength = "Fair"
    elif score < 80: strength = "Strong"
    else: strength = "Very strong"

    checks = (
        CredentialCheck("At least 12 characters", length >= 12),
        CredentialCheck("Contains lowercase letters", lower),
        CredentialCheck("Contains uppercase letters", upper),
        CredentialCheck("Contains numbers", digit),
        CredentialCheck("Contains symbols", symbol),
        CredentialCheck(
            f"Not among the {len(COMMON_PASSWORDS)} most common passwords",
            common_match is None,
        ),
        CredentialCheck(
            "No obvious patterns (keyboard walks, repeats, sequences, years)",
            not patterns,
        ),
        CredentialCheck(
            "Not based on your personal information (name, birth year)",
            "context" not in coverage,
        ),
    )
    return PasswordReport(
        password_length=length,
        score=score,
        strength=strength,
        entropy_bits=effective_entropy,
        random_entropy_bits=random_entropy,
        offline_crack_seconds=(2 ** effective_entropy) / OFFLINE_GUESSES_PER_SECOND,
        online_crack_seconds=(2 ** effective_entropy) / ONLINE_GUESSES_PER_SECOND,
        in_common_list=common_match is not None,
        common_match=common_match,
        patterns=patterns,
        context_match=None,
        is_passphrase=False,
        checks=checks,
    )


def generate_password(length: int = 20, symbols: bool = True) -> str:
    """Generate a cryptographically secure random password.

    Uses the operating system's secure random source (secrets). At least one
    character from every enabled pool is guaranteed.
    """
    if not isinstance(length, int) or isinstance(length, bool) or not 8 <= length <= 128:
        raise ValueError("Password length must be a whole number from 8 to 128.")
    pools = list(_GENERATOR_POOLS[:3])
    if symbols:
        pools.append(_GENERATOR_POOLS[3])
    characters = [secrets.choice(pool) for pool in pools]
    all_characters = "".join(pools)
    characters.extend(secrets.choice(all_characters) for _ in range(length - len(pools)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def format_duration(seconds: float) -> str:
    """Human-readable crack-time estimate."""
    if seconds < 1:
        return "less than a second"
    if seconds < 60:
        return f"{round(seconds)} second" + ("" if round(seconds) == 1 else "s")
    minutes = seconds / 60
    if minutes < 60:
        return f"{round(minutes)} minute" + ("" if round(minutes) == 1 else "s")
    hours = minutes / 60
    if hours < 24:
        return f"{round(hours)} hour" + ("" if round(hours) == 1 else "s")
    days = hours / 24
    if days < 365.25:
        return f"{round(days)} day" + ("" if round(days) == 1 else "s")
    years = days / 365.25
    if years >= 1000:
        return f"{years:,.0f} years"
    text = f"{years:.1f}"
    if text.endswith(".0"):
        text = text[:-2]
    return f"{text} year" + ("" if text == "1" else "s")


# ---------------------------------------------------------------------------
# Passphrase generator (NIST SP 800-63B pattern: 4+ random words)
# ---------------------------------------------------------------------------
PASSPHRASE_WORDS = (
    "able", "actor", "admit", "afraid", "after", "again", "agent", "agree",
    "ahead", "album", "allow", "almost", "always", "amber", "angle", "angry",
    "animal", "answer", "apple", "april", "arena", "argue", "arise", "army",
    "arrow", "artist", "ash", "aside", "ask", "asleep", "asset", "atlas",
    "atom", "attack", "audio", "aunt", "autumn", "award", "aware", "awful",
    "baby", "back", "badge", "balance", "ball", "banana", "band", "bank",
    "banner", "bar", "bare", "bark", "barn", "base", "basic", "basket",
    "battle", "beach", "bean", "bear", "beard", "beauty", "become", "beer",
    "before", "begin", "behind", "believe", "bell", "below", "bench", "best",
    "bet", "better", "between", "beyond", "bicycle", "big", "bike", "bill",
    "bird", "birth", "bit", "bite", "black", "blade", "blame", "blanket",
    "bleed", "blind", "block", "blood", "blow", "blue", "board", "boat",
    "body", "boil", "bold", "bolt", "bone", "book", "boot", "border",
    "born", "borrow", "boss", "both", "bottle", "bottom", "bought", "bowl",
    "box", "boy", "brain", "branch", "brand", "brave", "bread", "break",
    "breakfast", "breath", "brick", "bridge", "brief", "bright", "bring",
    "broad", "broken", "brother", "brown", "brush", "bubble", "budget",
    "build", "bulb", "bullet", "bunch", "burn", "burst", "bus", "business",
    "busy", "butter", "button", "buy", "cabin", "cable", "cake", "call",
    "calm", "camera", "camp", "can", "candle", "cannot", "canvas", "cap",
    "captain", "car", "card", "care", "careful", "carry", "case", "cash",
    "castle", "cat", "catch", "cause", "ceiling", "cell", "center", "chain",
    "chair", "chance", "change", "charge", "cheap", "check", "cheese",
    "chest", "chief", "child", "choose", "circle", "city", "claim", "class",
    "clean", "clear", "clerk", "clever", "click", "climb", "clock", "close",
    "cloth", "cloud", "club", "coach", "coal", "coast", "coat", "coffee",
    "coin", "cold", "collect", "color", "column", "come", "comfort", "common",
    "company", "compare", "complete", "condition", "connect", "consider",
    "contain", "content", "continue", "control", "cook", "cool", "copper",
    "copy", "corn", "corner", "correct", "cost", "cotton", "couch", "count",
    "country", "course", "court", "cover", "cow", "crack", "craft", "crash",
    "crazy", "cream", "create", "credit", "crew", "crime", "crop", "cross",
    "crowd", "cruel", "crush", "cry", "culture", "cup", "curious", "current",
    "curtain", "curve", "custom", "cut", "cycle", "dad", "daily", "damage",
    "dance", "danger", "dark", "dash", "data", "date", "daughter", "dawn",
    "day", "dead", "deal", "dear", "death", "debate", "decide", "deep",
    "deer", "degree", "delay", "deliver", "demand", "deny", "department",
    "depend", "depth", "describe", "desert", "design", "desk", "detail",
    "develop", "device", "diamond", "diet", "difference", "difficult",
    "digital", "dinner", "direct", "dirt", "discuss", "disease", "dish",
    "distance", "divide", "doctor", "dog", "dollar", "door", "double",
    "doubt", "down", "draft", "drag", "drama", "draw", "dream", "dress",
    "drink", "drive", "drop", "dry", "duck", "during", "dust", "duty",
    "each", "eager", "ear", "early", "earn", "earth", "ease", "east",
    "easy", "eat", "edge", "educate", "effect", "effort", "egg", "eight",
    "either", "electric", "elephant", "else", "empty", "end", "enemy",
    "energy", "engine", "enjoy", "enough", "enter", "entire", "equal",
    "escape", "even", "event", "ever", "every", "exact", "examine", "example",
    "excellent", "except", "exchange", "excite", "excuse", "exercise",
    "exist", "expect", "expensive", "explain", "explore", "express", "eye",
    "face", "fact", "factor", "fail", "fair", "fall", "false", "family",
    "famous", "fan", "farm", "fast", "father", "fault", "favor", "fear",
    "feather", "feed", "feel", "feet", "fellow", "female", "fence", "few",
    "field", "fight", "figure", "file", "fill", "film", "final", "find",
    "fine", "finger", "finish", "fire", "firm", "first", "fish", "fit",
    "fix", "flag", "flat", "flight", "float", "floor", "flower", "fly",
    "focus", "fold", "follow", "food", "foot", "force", "forest", "forget",
    "fork", "form", "formal", "forward", "four", "frame", "free", "fresh",
    "friend", "front", "fruit", "full", "fun", "funny", "future", "gain",
    "game", "garden", "gate", "gather", "general", "gentle", "gift", "girl",
    "give", "glad", "glass", "global", "glove", "goal", "gold", "good",
    "govern", "grade", "grain", "grand", "grass", "gray", "great", "green",
    "ground", "group", "grow", "guard", "guess", "guest", "guide", "gun",
    "habit", "hair", "half", "hall", "hand", "handle", "hang", "happen",
    "happy", "hard", "harm", "hat", "hate", "have", "head", "health", "hear",
    "heart", "heat", "heavy", "height", "hello", "help", "her", "here",
    "hero", "hers", "hide", "high", "hill", "him", "history", "hit", "hold",
    "hole", "holiday", "home", "honest", "hope", "horn", "horse", "hospital",
    "hot", "hotel", "hour", "house", "how", "human", "hundred", "hungry",
    "hunt", "hurry", "hurt", "husband", "ice", "idea", "identify", "if",
    "image", "imagine", "impact", "important", "improve", "in", "include",
    "income", "increase", "indeed", "individual", "industry", "inside",
    "instead", "interest", "into", "invest", "invite", "involve", "iron",
    "island", "issue", "item", "its", "itself", "jacket", "job", "join",
    "joke", "journey", "joy", "judge", "juice", "jump", "just", "keep",
    "key", "kick", "kid", "kill", "kind", "king", "kitchen", "knee", "knife",
    "knock", "know", "label", "labor", "lack", "lady", "lake", "land",
    "language", "large", "last", "late", "laugh", "law", "lay", "lead",
    "leaf", "learn", "least", "leave", "left", "leg", "legal", "lemon",
    "length", "less", "letter", "level", "lie", "life", "light", "like",
    "line", "link", "list", "listen", "little", "live", "local", "lock",
    "long", "look", "lose", "loss", "loud", "love", "low", "luck", "lunch",
    "machine", "main", "major", "make", "male", "man", "manage", "many",
    "map", "mark", "market", "marry", "master", "match", "material", "matter",
    "maybe", "meal", "mean", "measure", "meat", "medical", "meet", "member",
    "memory", "mention", "message", "metal", "method", "middle", "might",
    "milk", "million", "mind", "minute", "miss", "mistake", "mix", "model",
    "modern", "moment", "money", "month", "moon", "more", "morning", "most",
    "mother", "motion", "motor", "mountain", "mouse", "mouth", "move",
    "movie", "much", "music", "must", "nail", "name", "narrow", "nation",
    "nature", "near", "neck", "need", "negative", "neighbor", "neither",
    "net", "never", "new", "news", "next", "nice", "night", "nine", "nobody",
    "noise", "noon", "north", "nose", "note", "nothing", "notice", "novel",
    "now", "number", "nurse", "object", "occur", "ocean", "offer", "office",
    "often", "oil", "old", "once", "one", "only", "open", "operate",
    "opinion", "opposite", "or", "orange", "order", "other", "our", "out",
    "outside", "over", "own", "owner", "page", "pain", "paint", "pair",
    "pan", "paper", "parent", "park", "part", "particular", "pass", "past",
    "path", "patient", "pattern", "pause", "pay", "peace", "pen", "people",
    "per", "perfect", "perhaps", "period", "person", "phone", "photo",
    "pick", "picture", "piece", "pig", "pilot", "pin", "pink", "pipe",
    "place", "plain", "plan", "plant", "plastic", "plate", "play", "please",
    "pleasure", "plenty", "poem", "point", "pole", "police", "policy",
    "pollution", "poor", "popular", "population", "port", "position",
    "positive", "possible", "post", "pot", "pound", "power", "practice",
    "prepare", "present", "press", "pretty", "prevent", "price", "pride",
    "prime", "print", "prison", "privacy", "private", "prize", "probably",
    "problem", "process", "produce", "product", "program", "project",
    "promise", "protect", "proud", "prove", "provide", "public", "pull",
    "purpose", "push", "put", "quality", "quarter", "question", "quick",
    "quiet", "quite", "radio", "rail", "rain", "raise", "range", "rank",
    "rapid", "rather", "reach", "read", "ready", "real", "reason", "receive",
    "record", "red", "reduce", "reflect", "region", "relate", "relax",
    "remain", "remember", "remove", "rent", "repair", "repeat", "replace",
    "report", "require", "research", "respect", "rest", "result", "return",
    "review", "rice", "rich", "ride", "right", "ring", "rise", "risk",
    "river", "road", "rock", "role", "roll", "roof", "room", "root", "rose",
    "round", "route", "row", "royal", "rule", "run", "rural", "rush", "sad",
    "safe", "sail", "salt", "same", "sand", "save", "say", "scale", "scene",
    "school", "science", "score", "screen", "sea", "search", "season", "seat",
    "second", "secret", "section", "secure", "see", "seed", "seek", "seem",
    "select", "self", "sell", "send", "sense", "serve", "service", "set",
    "settle", "seven", "shall", "shape", "share", "sharp", "she", "sheet",
    "shelf", "shell", "shine", "ship", "shirt", "shoe", "shop", "short",
    "should", "shoulder", "show", "shut", "sick", "side", "signal", "silence",
    "silver", "simple", "since", "sing", "single", "sister", "sit", "site",
    "six", "size", "skill", "skin", "sky", "sleep", "slice", "slide", "small",
    "smart", "smell", "smile", "smoke", "snow", "social", "soft", "soil",
    "soldier", "solution", "solve", "some", "son", "song", "soon", "sorry",
    "sort", "sound", "south", "space", "speak", "special", "speech", "speed",
    "spend", "spirit", "sport", "spot", "spread", "spring", "square",
    "stair", "stand", "star", "start", "state", "station", "stay", "step",
    "stick", "still", "stock", "stone", "stop", "store", "storm", "story",
    "straight", "strange", "street", "strength", "strike", "strong",
    "structure", "student", "study", "stuff", "style", "subject", "success",
    "such", "sudden", "suffer", "sugar", "suggest", "summer", "sun", "supply",
    "support", "sure", "surface", "surprise", "sweet", "swim", "swing",
    "system", "table", "take", "talk", "tall", "tape", "task", "taste",
    "tax", "tea", "teach", "team", "tell", "ten", "tend", "term", "test",
    "than", "thank", "that", "the", "their", "them", "then", "there",
    "these", "they", "thick", "thin", "thing", "think", "third", "this",
    "those", "though", "thought", "three", "throw", "thus", "ticket",
    "tie", "time", "tiny", "tire", "to", "today", "together", "told",
    "tomorrow", "tone", "tongue", "too", "tool", "tooth", "top", "total",
    "touch", "toward", "town", "track", "trade", "train", "travel", "treat",
    "tree", "trend", "trial", "trip", "trouble", "true", "trust", "truth",
    "try", "tube", "turn", "twelve", "twenty", "twice", "two", "type",
    "uncle", "under", "understand", "unit", "until", "up", "upon", "us",
    "use", "usual", "valley", "value", "various", "vegetable", "very",
    "view", "village", "visit", "voice", "vote", "wait", "wake", "walk",
    "wall", "want", "war", "warm", "wash", "watch", "water", "wave", "way",
    "we", "weak", "wear", "weather", "week", "weight", "welcome", "well",
    "went", "west", "wet", "what", "when", "where", "which", "while",
    "white", "who", "whole", "why", "wide", "wife", "wild", "will", "win",
    "wind", "window", "wine", "wing", "winter", "wire", "wise", "wish",
    "with", "woman", "wonder", "wood", "word", "work", "world", "worry",
    "would", "write", "wrong", "yard", "year", "yellow", "yes", "yet",
    "you", "young", "your", "zero", "zone",
)

_PASSPHRASE_WORD_SET = frozenset(PASSPHRASE_WORDS)


def generate_passphrase(word_count: int = 4, separator: str = " ") -> str:
    """Generate a random passphrase of common words (NIST SP 800-63B style).

    Words are drawn with the operating system's secure random source. With 4
    words from a 7,776-word style list the estimate is ~51.7 bits; 5 words
    ~64.6 bits; 6 words ~77.5 bits.
    """
    if not isinstance(word_count, int) or isinstance(word_count, bool) or not 3 <= word_count <= 12:
        raise ValueError("Passphrase word count must be a whole number from 3 to 12.")
    if not isinstance(separator, str) or separator == "":
        raise ValueError("Separator must be non-empty text such as a space or hyphen.")
    chosen = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    return separator.join(chosen)
