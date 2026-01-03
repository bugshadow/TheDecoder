from ste import lsb

secret = "Message cache : TEST FORENSIC"
lsb.hide("test.jpg", secret).save("test_steno.jpg")
