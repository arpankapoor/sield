#include <gtk/gtk.h>
#include "sield-passwd-check.h"

static const gchar *glade_file = "sield.glade";
static int passwd_correct;

void on_ok_button_clicked(GtkWidget *ok_button, gpointer *data)
{
	GObject *dialog = G_OBJECT(data);

	GtkLabel *wrong_passwd_label = g_object_get_data(
					dialog, "wrong_passwd_label");

	GtkEntry *passwd_entry = g_object_get_data(dialog, "passwd_entry");
	const gchar *plain_txt_passwd = gtk_entry_get_text(passwd_entry);

	if (passwd_check(plain_txt_passwd)) {
		passwd_correct = 1;
		gtk_widget_destroy(GTK_WIDGET(dialog));
		gtk_main_quit();
	} else {
		/* Clear the password entry text area */
		gtk_entry_set_text(passwd_entry, "");
		gtk_widget_show(GTK_WIDGET(wrong_passwd_label));
	}
}

/*
 * Display the password input dialog.
 *
 * Return 1 if correct password is entered, else
 * return 0.
 */
int ask_passwd_dialog(const char *manufacturer,
	       const char *product)
{
	gtk_init(0, NULL);

	GtkBuilder *builder = gtk_builder_new_from_file(glade_file);

	GtkWidget *dialog = GTK_WIDGET(gtk_builder_get_object(
				builder, "dialog"));

	GtkLabel *device_info_label = GTK_LABEL(gtk_builder_get_object(
					builder, "device_info_label"));

	const gchar *str = "Authorization needed to mount and share";
	gtk_label_set_text(device_info_label, str);

	/*
	 * Pass passwd_entry and wrong_passwd_label to the "OK"
	 * button on being clicked.
	 */
	GtkEntry *passwd_entry = GTK_ENTRY(gtk_builder_get_object(
				builder, "passwd_entry"));
	GtkLabel *wrong_passwd_label = GTK_LABEL(gtk_builder_get_object(
				builder, "wrong_passwd_label"));

	g_object_set_data(G_OBJECT(dialog), "passwd_entry", passwd_entry);
	g_object_set_data(G_OBJECT(dialog), "wrong_passwd_label", wrong_passwd_label);

	gtk_builder_connect_signals(builder, dialog);

	g_object_unref(G_OBJECT(builder));

	/* Assume password is incorrect */
	passwd_correct = 0;
	gtk_widget_show(dialog);
	gtk_main();

	return passwd_correct;
}
