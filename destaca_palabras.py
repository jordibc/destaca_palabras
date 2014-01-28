#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Encuentra palabras interesantes en un grupo de ficheros con textos.
"""

from __future__ import division

import re
import argparse


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add = parser.add_argument  # por escribir menos
    add('--procesa', metavar='FICHERO', nargs='+', default=[], required=True,
        help='ficheros de texto a procesar para ver palabras interesantes')
    add('--aprende-de', metavar='FICHERO', nargs='+', default=[],
        help='ficheros de texto para aprender la frecuencia normal de palabras')
    add('--valores', action='store_true',
        help='muestra el factor de interés al lado de cada palabra')
    add('--verboso', action='store_true', help='explica los pasos que se dan')
    args = parser.parse_args()

    # Calcula la frecuencia de palabras en los textos que nos interesan.
    if args.verboso:
        print ('Calculando frecuencia de las palabras en los textos '
               'que nos interesan...')
    freqs = get_freqs(args.procesa, args.verboso)
    # freqs pinta como {'amigos': 0.00110365, "estaba": 0.00199798, ...}

    # Aquí podría haber un filtro que quitara todas las palabras
    # comunes, como "pero", "aun", "tampoco", etc, aunque no es necesario.

    # Calcula las frecuencias a priori usando textos "normales".
    if args.verboso:
        print ('Calculando frecuencia de las palabras en los textos '
               'normales...')
    priors = get_freqs(args.aprende_de, args.verboso)
    min_priors = min(v for k,v in priors.iteritems()) if priors else 1e-5

    # Muestra las palabras por orden de interés.
    if args.verboso:
        print 'Calculando interés relativo de las palabras...'
    score_words = [(interest(word, freq, priors, min_priors), word)
                   for word,freq in freqs.iteritems()]

    if args.verboso:
        print 'Resultados:'
    for score,word in sorted(score_words, reverse=True):
        if args.valores:
            print '%-12g %s' % (score, word)
        else:
            print word


def get_freqs(filepaths, verbose=False):
    """Devuelve un diccionario de frecuencia de aparición de palabras.

    Para cada palabra presente en un fichero de la lista "filepaths",
    cuenta el número de veces que aparece en total y calcula su
    frecuencia de aparición.

    """
    # Constantes que sirven para quitar luego tildes y similares.
    chars_ugly = u"ÁÉÍÓÚáéíóúÀÈÌÒÙàèìòùÄËÏÖÜäëïöüÑñÇçABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars_nice =  "aeiouaeiouaeiouaeiouaeiouaeiounnccabcdefghijklmnopqrstuvwxyz"
    tr = {ord(ugly): ord(nice) for ugly,nice in zip(chars_ugly, chars_nice)}

    freqs = {}
    total = 0
    for fname in filepaths:
        if verbose:
            print '  Leyendo %s' % fname
        try:
            text = (open(fname).read().decode('utf-8').translate(tr).
                    encode('ascii', errors='ignore'))
        except (IOError, UnicodeDecodeError) as e:
            print 'Problema con "%s" (ignoramos este fichero): %s' % (fname, e)
            continue
        for word in re.findall(r'\b[a-z][a-z0-9]{2,}\b', text):
            freqs.setdefault(word, 0)  # si word no estaba, freqs[word] = 0
            freqs[word] += 1
            total += 1

    # Normaliza la aparición de cada palabra, para tener su frecuencia.
    for w in freqs:
        freqs[w] /= total
    # Tal vez en lugar de eso podríamos estimar las frecuencias reales
    # usando "additive smoothing", pero seguramente no valga la pena
    # (https://en.wikipedia.org/wiki/Additive_smoothing).

    return freqs


def interest(word, freq, priors={}, min_priors=1e-5):
    """Devuelve el valor subjetivo de interés de una palabra.

    "word" es una palabra que se da con frecuencia "freq", y "priors"
    un diccionario con palabras como clave y la frecuencia con que se
    dan en textos normales, distintos del que estamos
    interesados. "min_priors" es el valor mínimo de frecuencia que se
    ve en todos los priors (lo podríamos calcular cada vez a partir de
    "priors", pero es más rápido hacerlo antes y pasarlo).

    """
    if word in priors:
        # La probabilidad a priori es la frecuencia con la que se da en "priors"
        prob = priors[word]
    else:
        # Si no la sabemos, estimamos esa probabilidad de alguna forma
        prob = min_priors / len(word)  #  teniendo en cuenta la Ley de Zipf

    # Medida de interés: ratio de verosimilitud (likelihood ratio)
    return freq / prob
    # Otras posibilidades que medirían el interés:
    #   return freq / min_priors # en principio no tan buena
    #   return freq / min_priors * len(word)  # lo mismo que sin prior ahora
    #
    # Y también podría ser interesante devolver el log() de eso, por
    # lo común que es usar el log likelihood ratio en la práctica.




if __name__ == '__main__':
    main()
