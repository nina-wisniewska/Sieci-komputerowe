# Sieciowe synchronizowanie zegarów

Projekt implementuje rozproszoną sieć synchronizacji zegarów w modelu *peer-to-peer*.  
Każdy węzeł komunikuje się z innymi przez UDP/IPv4, wybiera lidera i synchronizuje swój czas, uwzględniając opóźnienia w transmisji.

## Kluczowe funkcje
- Dynamiczne dołączanie węzłów do sieci  
- Wybór lidera jako źródła czasu  
- Synchronizacja zegarów z kompensacją opóźnień pakietów  
- Protokół własnego projektu, działający na komunikatach binarnych  
- Obsługa błędów i niepoprawnych komunikatów bez zatrzymywania pracy węzła  
