import { SelecteurTheme } from "../composants/SelecteurTheme";
import { Bouton } from "../composants/Bouton";
import { useBoutique } from "../lib/boutique";

/**
 * Vue du coffre déverrouillé. Provisoire (Jalon F2) : le Jalon F3 ajoutera la
 * barre latérale, la liste recherchable et le panneau de détail.
 */
export function EcranCoffre() {
  const apercu = useBoutique((b) => b.apercu);
  const verrouiller = useBoutique((b) => b.verrouiller);

  return (
    <div className="flex min-h-full flex-col">
      <header className="flex items-center justify-between border-b border-bordure px-6 py-3">
        <span className="font-semibold">NexKeyLock</span>
        <div className="flex items-center gap-2">
          <SelecteurTheme />
          <Bouton variante="secondaire" onClick={() => void verrouiller()}>
            Verrouiller
          </Bouton>
        </div>
      </header>
      <main className="flex flex-1 items-center justify-center p-8 text-center">
        <div className="flex flex-col items-center gap-2">
          <div className="text-4xl">🔓</div>
          <h1 className="text-xl font-semibold">Coffre déverrouillé</h1>
          <p className="text-texte-doux">
            {apercu?.nombreEntrees ?? 0} entrée(s). La vue complète arrive au Jalon F3.
          </p>
        </div>
      </main>
    </div>
  );
}
