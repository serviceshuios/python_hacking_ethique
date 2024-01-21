#!/usr/bin/env python3
# coding:utf-8
import time
import argparse
import atexit
from cracker import *
import  multiprocessing


def display_name():
    """
    Affiche la durée d'execution d'un programme
    :return:
    """
    print("Duree : " + str(time.time() - debut) + " secondes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Password Cracker")
    parser.add_argument("-f", "--file", dest="file", help="Path of the dictionary file", required=False)
    parser.add_argument("-g", "--gen", dest="gen", help="Generate MD5 hash of password", required=False)
    parser.add_argument("-md5", dest="md5", help="Hashed password (MD5)", required=False)
    parser.add_argument("-l", dest="plength", help="Password length", required=False, type=int)
    parser.add_argument("-o", dest="online", help="Cherche le hash en ligne (google)", required=False,
                        action="store_true")
    parser.add_argument("-p", dest="pattern", help="Utilise le motif de mot de passe (^=MAJ, *=MIN, ²=CHIFFRES")

    args = parser.parse_args()

    work_queue = multiprocessing.Queue()
    done_queue = multiprocessing.Queue()
    cracker = Cracker()
    debut = time.time()
    atexit.register(display_name)

    if args.md5:
        print("[*] CRACKING HASH " + args.md5)
        if args.file and not args.plength:
            print("[*] USING DICTIONARY FILE " + args.file)
            # lecture de fichier descendante
            p1 = multiprocessing.Process(target=Cracker.work, args=(work_queue, done_queue, args.md5, args.file, False))
            work_queue.put(cracker)
            p1.start()

            # lecture du fichier ascendante
            p2 = multiprocessing.Process(target=Cracker.work, args=(work_queue, done_queue, args.md5, args.file, True))
            work_queue.put(cracker)
            p2.start()

            while True:
                data = done_queue.get()
                if data == 'TROUVE' or data == 'NON TROUVE':
                    p1.kill()
                    p2.kill()
                    break

            #Cracker.crack_dict(args.md5, args.file)
        elif args.plength and not args.file:
            print("[*] USING INCREMENTAL MODE FOR " + str(args.plength) + " letter(s)")
            Cracker.crack_incr(args.md5, args.plength)
        elif args.online:
            print("[*] USING ONLINE MODE ")
            Cracker.crack_on_line(args.md5)
        elif args.pattern:
            print("[*] USING PASSWORD MODEL: " + args.pattern)
            Cracker.crack_smart(args.md5, args.pattern)
        else:
            print(Couleur.ROUGE + "[-] Please choose either -f or -l argument(s)" + Couleur.FIN)
    else:
        print(Couleur.ROUGE + "[-] MD5 hash not provided" + Couleur.FIN)
    if args.gen:
        print(Couleur.VERT + "[+] MD5 HASH OF " + args.gen + " : " + hashlib.md5(
            args.gen.encode("utf8")).hexdigest() + Couleur.FIN)
