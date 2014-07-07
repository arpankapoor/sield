#define _GNU_SOURCE             /* asprintf() */
#include <gtk/gtk.h>
#include <stdlib.h>             /* free() */
#include <string.h>             /* asprintf() */

#include "sield-config.h"           /* get_sield_attr_int() */
#include "sield-log.h"              /* log_fn() */
#include "sield-passwd-check.h"     /* passwd_correct() */
#include "sield-passwd-dialog.h"

struct passwd_widgets {
    GtkWidget *entry;
    GtkWidget *wrong_passwd_hbox;
    GtkWidget *wrong_passwd_label;
};

static int passwd_match;
static int passwd_try_no;
static long int MAX_PASSWD_TRIES;
static void passwd_response(GtkWidget *widget, int response, gpointer data);

/*
 * Display the password input dialog.
 *
 * Return 1 if correct password is entered, else return 0.
 */
int ask_passwd_dialog(const char *manufacturer, const char *product)
{
    GtkWidget *dialog = NULL;
    GtkWidget *image = NULL;
    GtkWidget *hbox = NULL;
    GtkWidget *label = NULL;
    GtkWidget *vbox_labels = NULL;
    GtkWidget *vbox_entries = NULL;
    GtkWidget *entry = NULL;
    GtkWidget *align = NULL;
    struct passwd_widgets *pwd_widgets = NULL;
    char *device_info = NULL;

    gtk_init(0, NULL);

    dialog = gtk_dialog_new();

    /* Cancel & OK buttons */
    gtk_dialog_add_button(GTK_DIALOG(dialog), GTK_STOCK_CANCEL,
                          GTK_RESPONSE_CANCEL);
    gtk_dialog_add_button(GTK_DIALOG(dialog), GTK_STOCK_OK, GTK_RESPONSE_OK);

    /* Default response is OK */
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK);

    /* Authentication image */
    image = gtk_image_new_from_stock(GTK_STOCK_DIALOG_AUTHENTICATION,
                                     GTK_ICON_SIZE_DIALOG);

    hbox = gtk_hbox_new(FALSE, 5);
    gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 12);

    /* Print device info */
    if (asprintf(&device_info, "%s %s inserted.\n"
                 "Authorization needed to mount and share.",
                 manufacturer, product) == -1) {
        device_info = strdup("USB block device inserted.\n"
                             "Authorization needed to mount and share.");
    }
    label = gtk_label_new(device_info);
    if (device_info) free(device_info);

    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 12);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
                       hbox, FALSE, TRUE, 5);

    /* Password label and entry */
    vbox_labels = gtk_vbox_new(FALSE, 5);
    vbox_entries = gtk_vbox_new(FALSE, 5);

    hbox = gtk_hbox_new(FALSE, 5);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
                       hbox, FALSE, TRUE, 5);

    gtk_box_pack_start(GTK_BOX(hbox), vbox_labels, FALSE, TRUE, 12);
    gtk_box_pack_start(GTK_BOX(hbox), vbox_entries, TRUE, TRUE, 12);

    align = gtk_alignment_new(0.0, 0.5, 0.0, 0.0);
    label = gtk_label_new("Password:");
    gtk_container_add(GTK_CONTAINER(align), label);
    gtk_box_pack_start(GTK_BOX(vbox_labels), align, TRUE, FALSE, 12);

    pwd_widgets = malloc(sizeof(struct passwd_widgets));

    /* Password entry */
    pwd_widgets->entry = entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox_entries), entry, TRUE, TRUE, 12);

    /* Wrong password label */
    pwd_widgets->wrong_passwd_hbox = hbox = gtk_hbox_new(FALSE, 5);

    /* Error image */
    image = gtk_image_new_from_stock(GTK_STOCK_DIALOG_ERROR,
                                     GTK_ICON_SIZE_BUTTON);
    gtk_box_pack_start(GTK_BOX(hbox), image, FALSE, FALSE, 12);

    label = gtk_label_new("Incorrect password. Please try again.");
    pwd_widgets->wrong_passwd_label = label;
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 12);
    gtk_box_pack_start(GTK_BOX(gtk_dialog_get_content_area(GTK_DIALOG(dialog))),
                       hbox, FALSE, TRUE, 5);

    /* Hide wrong password label. */
    gtk_widget_set_no_show_all(hbox, TRUE);

    g_signal_connect(G_OBJECT(dialog), "response", G_CALLBACK(passwd_response),
                     pwd_widgets);

    gtk_widget_show_all(
            GTK_WIDGET(gtk_dialog_get_content_area(GTK_DIALOG(dialog))));
    gtk_widget_show(dialog);

    passwd_match = 0;
    passwd_try_no = 1;
    MAX_PASSWD_TRIES = get_sield_attr_int("max password tries");
    if (MAX_PASSWD_TRIES == -1) MAX_PASSWD_TRIES = 3;

    gtk_main();

    if (pwd_widgets) free(pwd_widgets);
    return passwd_match;
}

static void passwd_response(GtkWidget *widget, int response, gpointer data)
{
    struct passwd_widgets *pwd_widgets = (struct passwd_widgets *) data;
    GtkWidget *pwd_entry = pwd_widgets->entry;
    GtkWidget *wrong_pwd_hbox = pwd_widgets->wrong_passwd_hbox;
    GtkWidget *wrong_pwd_label = pwd_widgets->wrong_passwd_label;
    const char *plain_txt_passwd = gtk_entry_get_text(GTK_ENTRY(pwd_entry));

    switch (response) {
    case GTK_RESPONSE_OK:
        if (is_passwd_correct(plain_txt_passwd)) {
            passwd_match = 1;
            gtk_widget_destroy(widget);
            gtk_main_quit();
        } else {
            passwd_match = 0;
            passwd_try_no++;

            /* Clear password entry text area */
            gtk_entry_set_text(GTK_ENTRY(pwd_entry), "");

            if (passwd_try_no == MAX_PASSWD_TRIES) {
                char *wrong_pwd = strdup("Incorrect password.\nLast attempt.");
                gtk_label_set_text(GTK_LABEL(wrong_pwd_label), wrong_pwd);
                if (wrong_pwd) free(wrong_pwd);
            }

            /* Show incorrect password label */
            gtk_widget_set_no_show_all(wrong_pwd_hbox, FALSE);
            gtk_widget_show_all(wrong_pwd_hbox);
            gtk_widget_show(wrong_pwd_hbox);
        }

        if (passwd_try_no <= MAX_PASSWD_TRIES) break;

    default:
        gtk_widget_destroy(widget);
        gtk_main_quit();
        break;
    }
}
