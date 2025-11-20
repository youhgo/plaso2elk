#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import traceback

from elasticsearch import Elasticsearch
# Importation de parallel_bulk ET streaming_bulk
from elasticsearch.helpers import parallel_bulk, streaming_bulk


class ElasticUploader:
    """Gère la connexion et l'envoi en masse des documents à Elasticsearch."""

    def __init__(self, es_hosts: list, es_user: str, es_pass: str, verify_ssl: bool = True, es_timeout: int = 60,
                 thread_count: int = 4, upload_mode: str = 'parallel'):
        try:
            # Ajout des paramètres de résilience : max_retries et retry_on_timeout
            es_options = {
                "basic_auth": (es_user, es_pass),
                "verify_certs": verify_ssl,
                "request_timeout": es_timeout,
                "max_retries": 10,  # Augmenter le nombre max de tentatives (par défaut 3)
                "retry_on_timeout": True  # Tenter une nouvelle connexion en cas de timeout
            }
            if not verify_ssl:
                import warnings
                from urllib3.exceptions import InsecureRequestWarning
                warnings.filterwarnings('ignore', category=InsecureRequestWarning)
                es_options["ca_certs"] = False
            self.client = Elasticsearch(es_hosts, **es_options)
            if not self.client.ping(): raise ConnectionError("La connexion à Elasticsearch a échoué.")
            print("Connexion à Elasticsearch réussie.")
            self.thread_count = thread_count
            self.upload_mode = upload_mode.lower()  # Stocke le mode (parallel ou streaming)
        except Exception as e:
            raise ConnectionError(f"Impossible d'initialiser le client Elasticsearch : {e}")

    def _create_index_template(self, template_name: str, index_pattern: str, priority: int = 400):
        """Crée ou met à jour un template d'index pour forcer le mapping de @timestamp."""
        template_body = {
            "index_patterns": [index_pattern],
            "priority": priority,  # Priorité dynamique
            "template": {
                "settings": {"index.mapping.total_fields.limit": 2000},
                "mappings": {
                    "properties": {"@timestamp": {"type": "date", "format": "strict_date_optional_time||epoch_millis"}}}
            }
        }
        try:
            self.client.indices.put_index_template(name=template_name, index_patterns=template_body["index_patterns"],
                                                   priority=template_body["priority"],
                                                   template=template_body["template"])
            print(
                f"Template d'index '{template_name}' pour le pattern '{index_pattern}' créé/mis à jour (Priorité: {priority}).")
        except Exception as e:
            print(f"[Attention] Impossible de créer le template d'index '{template_name}'. Erreur: {e}")

    def setup_templates(self, **kwargs):
        """Configure les templates pour les différents types de logs."""
        # On force la priorité à 400 pour éviter les conflits avec d'anciens templates de priorité 300
        for name, pattern in kwargs.items():
            self._create_index_template(f"forensic_{name}_template", pattern, priority=400)

    def bulk_upload(self, actions_generator, chunk_size: int):
        """Envoie des documents depuis un générateur en utilisant le mode d'envoi spécifié (parallel ou streaming)."""

        # Sélection de la fonction d'envoi et affichage du statut
        if self.upload_mode == 'parallel':
            bulk_func = parallel_bulk
            print(
                f"\n[MODE: PARALLÈLE] Envoi des documents par lots de {chunk_size} avec {self.thread_count} threads...")
            bulk_kwargs = {'thread_count': self.thread_count}
        else:
            bulk_func = streaming_bulk
            print(f"\n[MODE: STREAMING] Envoi des documents séquentiel par lots de {chunk_size}...")
            bulk_kwargs = {}  # Pas de thread_count pour streaming_bulk

        success_count, fail_count = 0, 0
        try:
            # Utilisation de la fonction et des arguments appropriés
            for ok, result in bulk_func(
                    client=self.client,
                    actions=actions_generator,
                    chunk_size=chunk_size,
                    raise_on_error=False,
                    raise_on_exception=False,
                    **bulk_kwargs
            ):
                if ok:
                    success_count += 1
                else:
                    fail_count += 1
                    print(f"\n[ERREUR D'ENVOI] Document échoué : {json.dumps(result, indent=2)}")

            print("\nEnvoi terminé.")
            print(f"Documents envoyés avec succès : {success_count}")
            if fail_count > 0:
                print(f"Documents en échec : {fail_count}")
        except Exception as e:
            print(f"Une erreur critique est survenue durant l'envoi en streaming : {traceback.format_exc()}")