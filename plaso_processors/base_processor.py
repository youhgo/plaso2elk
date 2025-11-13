#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timedelta, timezone
import re


class BaseEventProcessor:
    """Classe de base abstraite pour tous les processeurs d'événements Plaso."""

    def process_event(self, event: dict) -> (dict, str):
        """
        Traite un événement (dictionnaire) Plaso.

        Args:
            event (dict): Le dictionnaire JSON d'un événement Plaso.

        Returns:
            tuple (dict, str):
                - Le dictionnaire d'événement modifié/enrichi.
                - La clé de type d'index (ex: "evtx_security", "mft", "hive_software").
        """
        raise NotImplementedError("La méthode process_event doit être implémentée par la sous-classe.")

    # --- Fonctions Utilitaires (Anciennement dans PlasoToELK) ---

    @staticmethod
    def drop_useless_fields(event: dict):
        """Supprime les champs Plaso verbeux pour alléger le document final."""
        l_field_to_drop = [
            "__container_type__", "__type__", "date_time", "_event_values_hash",
            "display_name", "inode", "pathspec", "strings", "message",
            "xml_string",  # Gardé dans 'Data' pour evtx, supprimé du niveau racine
            "event_version", "message_identifier", "offset", "provider_identifier",
            "recovered", "timestamp"  # Remplacé par 'estimestamp'
        ]
        # Champs MFT/LNK importants à conserver (s'ils existent)
        # "is_allocated", "file_reference"

        for field in l_field_to_drop:
            event.pop(field, None)
        return event

    # --- Fonctions Utilitaires de Timestamp (Anciennement dans PlasoToELK) ---

    @staticmethod
    def _parse_filetime_to_dt(filetime_int):
        if not isinstance(filetime_int, int): return None
        try:
            _FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
            microseconds = filetime_int / 10
            return _FILETIME_EPOCH + timedelta(microseconds=microseconds)
        except Exception:
            return None

    @staticmethod
    def _parse_unix_micro_to_dt(unix_micro):
        if not isinstance(unix_micro, int): return None
        try:
            return datetime.fromtimestamp(unix_micro / 1e6, tz=timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _parse_iso_string_to_dt(iso_string):
        if not iso_string: return None
        try:
            iso_string = re.sub(r'(\.\d{6})\d+Z$', r'\1Z', iso_string)
            return datetime.strptime(iso_string, '%Y-%m-%dT%H:%M:%S.%f%z')
        except ValueError:
            try:
                return datetime.strptime(iso_string, '%Y-%m-%dT%H:%M:%S%z')
            except Exception:
                return None
        except Exception:
            return None

    @staticmethod
    def _format_dt_to_es(dt_obj):
        if not isinstance(dt_obj, datetime): return None
        if dt_obj.tzinfo is None:
            dt_obj = dt_obj.replace(tzinfo=timezone.utc)
        return dt_obj.isoformat(timespec='microseconds').replace('+00:00', 'Z')