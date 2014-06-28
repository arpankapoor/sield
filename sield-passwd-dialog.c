#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>

#include "sield-log.h"
#include "sield-passwd-check.h"
#include "sield-passwd-dialog.h"

struct passwd_data {
	GtkWidget *entry;
	GtkWidget *wrong_passwd;
};

static int passwd_correct;
static void passwd_response(GtkWidget *widget, int response, gpointer data);

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

	GtkWidget *dialog = gtk_dialog_new();

	/* Cancel & OK buttons */
	gtk_dialog_add_button(GTK_DIALOG(dialog),
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL);
	gtk_dialog_add_button(GTK_DIALOG(dialog),
		GTK_STOCK_OK, GTK_RESPONSE_OK);

	/* Authentication image */
	GtkWidget *image = gtk_image_new_from_stock(
		GTK_STOCK_DIALOG_AUTHENTICATION, GTK_ICON_SIZE_DIALOG);

	/* Default response is OK */
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
					GTK_RESPONSE_OK);

	GtkWidget *hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 12);

	/* Print device info */
	char *dev_info = NULL;
	if (asprintf(&dev_info, "%s %s inserted.\n"
			"Authorization needed to mount and share.",
			manufacturer, product) == -1) {
		dev_info = strdup("USB block device inserted.\n"
				"Authorization needed to mount and share.");
	}

	GtkWidget *label = gtk_label_new(dev_info);
	if (dev_info) free(dev_info);

	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 12);
	gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
			hbox, FALSE, TRUE, 5);

	/* Password label and entry */
	GtkWidget *vbox_labels = gtk_vbox_new(FALSE, 5);
	GtkWidget *vbox_entries = gtk_vbox_new(FALSE, 5);

	hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
		hbox, FALSE, TRUE, 5);

	gtk_box_pack_start(GTK_BOX(hbox), vbox_labels, FALSE, TRUE, 12);
	gtk_box_pack_start(GTK_BOX(hbox), vbox_entries, TRUE, TRUE, 12);

	GtkWidget *align = gtk_alignment_new(0.0, 0.5, 0.0, 0.0);
	label = gtk_label_new("Password:");
	gtk_container_add(GTK_CONTAINER(align), label);

	gtk_box_pack_start(GTK_BOX(vbox_labels), align, TRUE, FALSE, 12);

	struct passwd_data *password_data = malloc(sizeof password_data);
	password_data->entry = gtk_entry_new();
	gtk_entry_set_visibility(GTK_ENTRY(password_data->entry), FALSE);
	gtk_entry_set_activates_default(GTK_ENTRY(password_data->entry),
				TRUE);

	gtk_box_pack_start(GTK_BOX(vbox_entries),
			password_data->entry, TRUE, TRUE, 12);

	/* Wrong password label. */
	password_data->wrong_passwd = hbox = gtk_hbox_new(FALSE, 5);

	image = gtk_image_new_from_stock(
		GTK_STOCK_DIALOG_ERROR, GTK_ICON_SIZE_BUTTON);
	gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 12);

	label = gtk_label_new("Incorrect password. Please try again.");
	gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 12);
	gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
			hbox, FALSE, TRUE, 5);

	/* Hide wrong password label. */
	gtk_widget_set_no_show_all(hbox, TRUE);

	g_signal_connect(G_OBJECT(dialog), "response",
			G_CALLBACK(passwd_response), password_data);

	gtk_widget_show_all(GTK_WIDGET(gtk_dialog_get_content_area(GTK_DIALOG(dialog))));
	gtk_widget_show(dialog);

	passwd_correct = 0;
	gtk_main();

	free(password_data);
	return passwd_correct;
}

static void passwd_response(GtkWidget *widget, int response, gpointer data)
{
	struct passwd_data *password_data = (struct passwd_data *) data;
	const gchar *plain_txt_passwd = gtk_entry_get_text(GTK_ENTRY(password_data->entry));
	switch (response) {
	case GTK_RESPONSE_OK:
		if (passwd_check(plain_txt_passwd)) {
			passwd_correct = 1;
			gtk_widget_destroy(widget);
			gtk_main_quit();
		} else {
			passwd_correct = 0;

			/* Clear password entry text area */
			gtk_entry_set_text(GTK_ENTRY(password_data->entry), "");

			/* Show incorrect password label */
			gtk_widget_set_no_show_all(password_data->wrong_passwd, FALSE);
			gtk_widget_show_all(password_data->wrong_passwd);
			gtk_widget_show(password_data->wrong_passwd);
		}
		break;
	default:
		gtk_widget_destroy(widget);
		gtk_main_quit();
		break;
	}
}
