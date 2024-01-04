a = b = c = d = e = 0
d.a = c.a = 5
#a.x uninitialized -> 1 vulnerability
sink(a.x)
a.x = f("xxx", c + d.a, c.a)
#a.x initialized with no taint -> 0 vulnerabilities
sink(a.x)
a.x = spooky(b, "hi" + "bye") + scary("scary")
a.x = san(a.x)
#a.x sanitized after being tainted by two sources -> 2 vulnerabilities
sink(a.x)
#nested sources and sanitizer
sink2 = abc(san(defg(hi()))) #-> 3 vulnerabilities