import os
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import sv_ttk

from source.vault import IntegrityError, Vault

class PremiumVaultApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecureVault Premium")
        self.root.geometry("1000x700")
        
        # Appliquer le thème Sun Valley
        sv_ttk.set_theme("light")
        self.style = ttk.Style()
        self._setup_styles()
        
        # UI
        self._create_main_frame()
        self._create_header()
        self._create_vault_controls()
        self._setup_tabs()
        
        self.vault = None
        # Compteur anti-bruteforce géré ici car il est lié à la session GUI
        self._failed_attempts = 0
        self._locked_until = 0.0

    def _setup_styles(self):
        """Configure les styles premium"""
        self.style.configure('Premium.TFrame', background='#f8f9fa')
        self.style.configure('Premium.TLabel', font=('Segoe UI', 12), background='#f8f9fa')
        self.style.configure('Premium.TButton', font=('Segoe UI', 10, 'bold'), padding=10)
        self.style.configure('Premium.TNotebook', background='#f8f9fa')
        self.style.configure('Premium.TNotebook.Tab', padding=[15, 5], font=('Segoe UI', 10, 'bold'))

    def _create_main_frame(self):
        """Frame principal"""
        self.main_frame = ttk.Frame(self.root, style='Premium.TFrame')
        self.main_frame.pack(fill=tk.BOTH, expand=True)

    def _create_header(self):
        """En-tête avec logo"""
        header = ttk.Frame(self.main_frame, style='Premium.TFrame')
        header.pack(fill=tk.X, pady=(0, 20), padx=20)
        
        logo_label = ttk.Label(header, text="🔒 SecureVault", font=('Segoe UI', 24, 'bold'))
        logo_label.pack(side=tk.LEFT)
        
        self.theme_btn = ttk.Button(header, text="Mode Sombre", command=self._toggle_theme)
        self.theme_btn.pack(side=tk.RIGHT)

    def _toggle_theme(self):
        """Bascule entre light/dark mode"""
        current = sv_ttk.get_theme()
        sv_ttk.set_theme("dark" if current == "light" else "light")
        self.theme_btn.config(text="Mode Clair" if current == "dark" else "Mode Sombre")

    def _create_vault_controls(self):
        """Contrôles du vault"""
        control_frame = ttk.LabelFrame(self.main_frame, text="Contrôle du Vault", style='Premium.TFrame')
        control_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # Champ chemin du vault
        ttk.Label(control_frame, text="Chemin:").grid(row=0, column=0, padx=5, pady=5)
        self.vault_path_entry = ttk.Entry(control_frame, width=40)
        self.vault_path_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(control_frame, text="Parcourir", command=self._browse_vault_path).grid(row=0, column=2, padx=5)
        
        # Champ mot de passe
        ttk.Label(control_frame, text="Mot de passe:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(control_frame, show="*", width=40)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Boutons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=10)
        ttk.Button(btn_frame, text="Créer Vault", command=self._create_vault).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Ouvrir Vault", command=self._open_vault).pack(side=tk.LEFT, padx=5)

    def _setup_tabs(self):
        """Configure les onglets fonctionnels"""
        self.notebook = ttk.Notebook(self.main_frame, style='Premium.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        
        # Onglet Ajout
        self.add_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.add_tab, text="Ajouter Fichier")
        ttk.Button(self.add_tab, text="Sélectionner Fichier", command=self._add_file).pack(pady=20)
        
        # Onglet Liste
        self.list_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.list_tab, text="Lister Fichiers")
        list_actions = ttk.Frame(self.list_tab)
        list_actions.pack(fill=tk.X, padx=10, pady=(10, 0))
        ttk.Button(
            list_actions,
            text="Supprimer le fichier sélectionné",
            command=self._delete_file,
        ).pack(side=tk.LEFT)
        self.file_list = ScrolledText(self.list_tab, state=tk.DISABLED, font=('Consolas', 10))
        self.file_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Onglet Extraction
        self.extract_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.extract_tab, text="Extraire Fichier")
        ttk.Label(self.extract_tab, text="Nom du fichier:").pack(pady=(10, 0))
        self.extract_name_entry = ttk.Entry(self.extract_tab)
        self.extract_name_entry.pack(fill=tk.X, padx=20, pady=5)
        ttk.Label(self.extract_tab, text="Dossier de destination:").pack()
        self.extract_path_entry = ttk.Entry(self.extract_tab)
        self.extract_path_entry.pack(fill=tk.X, padx=20, pady=5)
        ttk.Button(self.extract_tab, text="Parcourir", command=self._browse_extract_path).pack()
        ttk.Button(self.extract_tab, text="Extraire", command=self._extract_file).pack(pady=10)
        
        # Onglet Mot de passe
        self.pass_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.pass_tab, text="Changer MDP")
        ttk.Label(self.pass_tab, text="Nouveau mot de passe:").pack(pady=(10, 0))
        self.new_pass_entry = ttk.Entry(self.pass_tab, show="*")
        self.new_pass_entry.pack(fill=tk.X, padx=20, pady=5)
        ttk.Button(self.pass_tab, text="Changer Mot de Passe", command=self._change_password).pack(pady=10)

    def _browse_vault_path(self):
        path = filedialog.asksaveasfilename(defaultextension=".lbox", filetypes=[("Vault Files", "*.lbox")])
        if path:
            self.vault_path_entry.delete(0, tk.END)
            self.vault_path_entry.insert(0, path)

    def _create_vault(self):
        path = self.vault_path_entry.get()
        password = self.password_entry.get()
        
        if not path or not password:
            messagebox.showerror("Erreur", "Chemin et mot de passe requis")
            return
            
        try:
            self.vault = Vault(path, password)
            self.vault.create_vault()
            messagebox.showinfo("Succès", "Vault créé avec succès")
            self._enable_interface()
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur de création: {str(e)}")

    def _open_vault(self):
        if time.time() < self._locked_until:
            remaining = int(self._locked_until - time.time())
            messagebox.showerror("Verrouillé", f"Trop de tentatives. Réessayez dans {remaining} secondes.")
            return

        path = self.vault_path_entry.get()
        password = self.password_entry.get()

        if not path or not password:
            messagebox.showerror("Erreur", "Chemin et mot de passe requis")
            return

        try:
            self.vault = Vault(path, password)
            self.vault.load_vault()
            self._failed_attempts = 0
            self._locked_until = 0.0
            messagebox.showinfo("Succès", "Vault ouvert avec succès")
            self._enable_interface()
            self._update_file_list()
        except (IntegrityError, Exception) as e:
            self._failed_attempts += 1
            if self._failed_attempts >= 3:
                self._locked_until = time.time() + 30
                messagebox.showerror("Verrouillé", "Trop de tentatives. Réessayez dans 30 secondes.")
            elif isinstance(e, IntegrityError):
                messagebox.showerror("Erreur", "Mot de passe incorrect ou vault corrompu.")
            else:
                messagebox.showerror("Erreur", f"Erreur d'ouverture : {e}")

    def _enable_interface(self):
        """Active les fonctionnalités après ouverture"""
        self.notebook.tab(0, state="normal")
        self.notebook.tab(1, state="normal")
        self.notebook.tab(2, state="normal")
        self.notebook.tab(3, state="normal")
        self._update_file_list()

    def _add_file(self):
        if not self.vault:
            messagebox.showerror("Erreur", "Ouvrez d'abord un vault")
            return
            
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
            
        try:
            self.vault.add_file(file_path)
            messagebox.showinfo("Succès", "Fichier ajouté avec succès")
            self._update_file_list()
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur d'ajout: {str(e)}")

    def _extract_file(self):
        if not self.vault:
            messagebox.showerror("Erreur", "Ouvrez d'abord un vault")
            return
            
        filename = self.extract_name_entry.get()
        output_path = self.extract_path_entry.get()
        
        if not filename or not output_path:
            messagebox.showerror("Erreur", "Nom du fichier et dossier requis")
            return
            
        try:
            self.vault.extract_file(filename, os.path.join(output_path, filename))
            messagebox.showinfo("Succès", f"Fichier '{filename}' extrait avec succès")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur d'extraction: {str(e)}")

    def _delete_file(self):
        if not self.vault:
            messagebox.showerror("Erreur", "Ouvrez d'abord un vault")
            return

        selection = self.file_list.tag_ranges(tk.SEL)
        if not selection:
            messagebox.showerror("Erreur", "Sélectionnez le nom d'un fichier dans la liste")
            return

        selected = self.file_list.get(selection[0], selection[1]).strip()
        filename = selected.splitlines()[0].strip().lstrip("- ")
        if not filename or filename not in self.vault.list_files():
            messagebox.showerror("Erreur", "Sélectionnez un nom de fichier valide")
            return

        if not messagebox.askyesno("Confirmation", f"Supprimer '{filename}' du vault ?"):
            return
        try:
            self.vault.delete_file(filename)
            messagebox.showinfo("Succès", "Fichier supprimé")
            self._update_file_list()
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur de suppression: {str(e)}")

    def _change_password(self):
        if not self.vault:
            messagebox.showerror("Erreur", "Ouvrez d'abord un vault")
            return
            
        new_password = self.new_pass_entry.get()
        if not new_password:
            messagebox.showerror("Erreur", "Nouveau mot de passe requis")
            return
            
        try:
            self.vault.change_password(new_password)
            messagebox.showinfo("Succès", "Mot de passe changé avec succès")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur changement de mot de passe: {str(e)}")

    def _update_file_list(self):
        if not self.vault:
            return
            
        try:
            files = self.vault.list_files()
            self.file_list.config(state=tk.NORMAL)
            self.file_list.delete(1.0, tk.END)
            if not files:
                self.file_list.insert(tk.END, "Le vault est vide")
            else:
                self.file_list.insert(tk.END, "Fichiers dans le vault:\n")
                for f in files:
                    self.file_list.insert(tk.END, f" - {f}\n")
            self.file_list.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur mise à jour liste: {str(e)}")

    def _browse_extract_path(self):
        path = filedialog.askdirectory()
        if path:
            self.extract_path_entry.delete(0, tk.END)
            self.extract_path_entry.insert(0, path)

if __name__ == "__main__":
    app = PremiumVaultApp()
    app.root.mainloop()
