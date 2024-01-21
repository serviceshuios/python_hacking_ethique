import hashlib
import string
import sys
import urllib.request
import urllib.response
import urllib.error
from utils import *


class Cracker:
    @staticmethod
    def crack_dict(md5, file, order, done_queue):
        """
        casse un HASH MD5 via une liste de mots-clés (file)
        :param done_queue: queue des taches terminées
        :param order: ordre de lecture du fichier (ascendant ou descendant)
        :param md5: HASH md5 à casser
        :param file: fichier de mots-clé à utiliser
        :return:
        """
        try:
            trouve = False
            ofile = open(file, "r")
            if Order.ASCEND == order:
                contenu = reversed(list(ofile.readlines()))
            else:
                contenu = ofile.readlines()
            for mot in contenu:
                mot = mot.strip("\n").encode("utf-8")
                hashmd5 = hashlib.md5(mot).hexdigest()
                if hashmd5 == md5:
                    print(Couleur.VERT + "[+]Mot de passe trouvé : " + str(mot) + "(" + hashmd5 + ")" + Couleur.FIN)
                    trouve = True
                    done_queue.put("TROUVE")
                    break
            if not trouve:
                print(Couleur.ROUGE + "[-]Mot de passe non trouvé" + Couleur.FIN)
                done_queue.put("NON TROUVE")
            ofile.close()
        except FileNotFoundError:
            print(Couleur.ROUGE + "[-]Erreur : fichier introuvable" + Couleur.FIN)
            sys.exit(1)
        except Exception as err:
            print(Couleur.ROUGE + "[-]Erreur : " + str(err) + Couleur.FIN)
            sys.exit(2)

    @staticmethod
    def crack_incr(md5, length, _currpass=[]):
        """
        casse un HASH MD5 via une méthode incrémentale pour un mdp de longueur length
        :param md5: Le hash md5 à casser
        :param length: La longueur du mot de passe à trouver
        :param _currpass: liste temporaire automatique utilisée via récursion contenant l'essai de mpd actuel
        :return:
        """
        lettres = string.ascii_letters
        if length >= 1:
            if len(_currpass) == 0:
                _currpass = ['a' for _ in range(length)]
                Cracker.crack_incr(md5, length, _currpass)
            else:
                for c in lettres:
                    _currpass[length - 1] = c
                    mdp = "".join(_currpass)
                    print("[*]Trying : " + mdp)
                    if hashlib.md5(mdp.encode("utf8")).hexdigest() == md5:
                        print(Couleur.VERT + "[+]PASSWORD FOUND :" + mdp + Couleur.FIN)
                        sys.exit(0)
                    else:
                        Cracker.crack_incr(md5, length - 1, _currpass)
        else:
            return

    @staticmethod
    def crack_on_line(md5):
        """
        Cherche le Hash md5 via google
        :param md5: hash md5 à utiliser pour la recherche en ligne
        :return:
        """
        try:
            agent_utilisateur = "Mozilla/5.0 (Windows; U; Windows NT 5.1; fr-FR; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7"
            headers = {'User-Agent': agent_utilisateur}
            url = "https://www.google.fr/search?hl=fr&q=" + md5
            requete = urllib.request.Request(url, None, headers)
            response = urllib.request.urlopen(requete)
        except urllib.error.HTTPError as e:
            print("Erreur Http : " + e.code)
        except urllib.error.URLError as e:
            print("Erreur Http : " + e.reason)

        if "Aucun document" in str(response.read()):
            print(Couleur.ROUGE + "[-] HASH NON TROUVE VIA GOOGLE " + Couleur.FIN)
        else:
            print(Couleur.VERT + "[+] HASH  TROUVE VIA GOOGLE " + url + Couleur.FIN)

    @staticmethod
    def crack_smart(md5, pattern, _index=0):
        """

        :param md5:
        :param pattern:
        :param _index:
        :return:
        """
        MAJ = string.ascii_uppercase
        CHIFFRES = string.digits
        MIN = string.ascii_lowercase

        if _index < len(pattern):
            if "^" == pattern[_index]:
                for c in MAJ:
                    p = pattern.replace("^", c, 1)
                    currhash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currhash == md5:
                        print(Couleur.VERT + "[+] MOT DE PASSE TROUVE " + p + Couleur.FIN)
                        sys.exit(0)
                    print("MAJ : " + p + " (" + currhash + ")")
                    Cracker.crack_smart(md5, p, _index + 1)

            if "*" == pattern[_index]:
                for c in MIN:
                    p = pattern.replace("*", c, 1)
                    currhash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currhash == md5:
                        print(Couleur.VERT + "[+] MOT DE PASSE TROUVE " + p + Couleur.FIN)
                        sys.exit(0)
                    print("MIN : " + p + " (" + currhash + ")")
                    Cracker.crack_smart(md5, p, _index + 1)

            if "²" == pattern[_index]:
                for c in CHIFFRES:
                    p = pattern.replace("²", c, 1)
                    currhash = hashlib.md5(p.encode("utf8")).hexdigest()
                    if currhash == md5:
                        print(Couleur.VERT + "[+] MOT DE PASSE TROUVE " + p + Couleur.FIN)
                        sys.exit(0)
                    print("CHIFFRE : " + p + " (" + currhash + ")")
                    Cracker.crack_smart(md5, p, _index + 1)
        else:
            return

    @staticmethod
    def work(work_queue, done_queue, md5, file, order):
        """

        :param work_queue:
        :param done_queue:
        :param md5:
        :param file:
        :param order:
        :return:
        """
        o = work_queue.get()
        o.crack_dict(md5, file, order, done_queue)
